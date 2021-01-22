// Copyright 2015 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"flag"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/user"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/prometheus/common/promlog"
	"github.com/prometheus/common/promlog/flag"

	"github.com/prometheus/common/promlog"
	"github.com/prometheus/common/promlog/flag"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/version"
	"github.com/prometheus/exporter-toolkit/web"
	"github.com/prometheus/node_exporter/collector"
	"gopkg.in/ini.v1"

	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

// handler wraps an unfiltered http.Handler but uses a filtered handler,
// created on the fly, if filtering is requested. Create instances with
// newHandler.
type handler struct {
	unfilteredHandler http.Handler
	// exporterMetricsRegistry is a separate registry for the metrics about
	// the exporter itself.
	exporterMetricsRegistry *prometheus.Registry
	includeExporterMetrics  bool
	maxRequests             int
	logger                  log.Logger
}

var cfg = new(config)
var (
	configPath        = flag.String("config", "/opt/ss/ssm-client/node_exporter.conf", "Path of config file")
	enabledCollectors = flag.String("collectors.enabled", filterAvailableCollectors(defaultCollectors), "Comma-separated list of collectors to use.")
	printCollectors   = flag.Bool("collectors.print", false, "If true, print available collectors and exit.")
)

func newHandler(includeExporterMetrics bool, maxRequests int, logger log.Logger) *handler {
	h := &handler{
		exporterMetricsRegistry: prometheus.NewRegistry(),
		includeExporterMetrics:  includeExporterMetrics,
		maxRequests:             maxRequests,
		logger:                  logger,
	}
	if h.includeExporterMetrics {
		h.exporterMetricsRegistry.MustRegister(
			prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}),
			prometheus.NewGoCollector(),
		)
	}
	if innerHandler, err := h.innerHandler(); err != nil {
		panic(fmt.Sprintf("Couldn't create metrics handler: %s", err))
	} else {
		h.unfilteredHandler = innerHandler
	}
	return h
}

// ServeHTTP implements http.Handler.
func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	filters := r.URL.Query()["collect[]"]
	level.Debug(h.logger).Log("msg", "collect query:", "filters", filters)

	if len(filters) == 0 {
		// No filters, use the prepared unfiltered handler.
		h.unfilteredHandler.ServeHTTP(w, r)
		return
	}
	// To serve filtered metrics, we create a filtering handler on the fly.
	filteredHandler, err := h.innerHandler(filters...)
	if err != nil {
		level.Warn(h.logger).Log("msg", "Couldn't create filtered metrics handler:", "err", err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("Couldn't create filtered metrics handler: %s", err)))
		return
	}
	filteredHandler.ServeHTTP(w, r)
}

// innerHandler is used to create both the one unfiltered http.Handler to be
// wrapped by the outer handler and also the filtered handlers created on the
// fly. The former is accomplished by calling innerHandler without any arguments
// (in which case it will log all the collectors enabled via command-line
// flags).
func (h *handler) innerHandler(filters ...string) (http.Handler, error) {
	nc, err := collector.NewNodeCollector(h.logger, filters...)
	if err != nil {
		return nil, fmt.Errorf("couldn't create collector: %s", err)
	}

	// Only log the creation of an unfiltered handler, which should happen
	// only once upon startup.
	if len(filters) == 0 {
		level.Info(h.logger).Log("msg", "Enabled collectors")
		collectors := []string{}
		for n := range nc.Collectors {
			collectors = append(collectors, n)
		}
		sort.Strings(collectors)
		for _, c := range collectors {
			level.Info(h.logger).Log("collector", c)
		}
	}

	r := prometheus.NewRegistry()
	r.MustRegister(version.NewCollector("node_exporter"))
	if err := r.Register(nc); err != nil {
		return nil, fmt.Errorf("couldn't register node collector: %s", err)
	}
	handler := promhttp.HandlerFor(
		prometheus.Gatherers{h.exporterMetricsRegistry, r},
		promhttp.HandlerOpts{
			ErrorHandling:       promhttp.ContinueOnError,
			MaxRequestsInFlight: h.maxRequests,
			Registry:            h.exporterMetricsRegistry,
		},
	)
	if h.includeExporterMetrics {
		// Note that we have to use h.exporterMetricsRegistry here to
		// use the same promhttp metrics for all expositions.
		handler = promhttp.InstrumentMetricHandler(
			h.exporterMetricsRegistry, handler,
		)
	}
	return handler, nil
}

func main() {
	flag.Parse()
	var (
		listenAddress = kingpin.Flag(
			"web.listen-address",
			"Address on which to expose metrics and web interface.",
		).Default(":9100").String()
		metricsPath = kingpin.Flag(
			"web.telemetry-path",
			"Path under which to expose metrics.",
		).Default("/metrics").String()
		disableExporterMetrics = kingpin.Flag(
			"web.disable-exporter-metrics",
			"Exclude metrics about the exporter itself (promhttp_*, process_*, go_*).",
		).Bool()
		maxRequests = kingpin.Flag(
			"web.max-requests",
			"Maximum number of parallel scrape requests. Use 0 to disable.",
		).Default("40").Int()
		disableDefaultCollectors = kingpin.Flag(
			"collector.disable-defaults",
			"Set all collectors to disabled by default.",
		).Default("false").Bool()
		configFile = kingpin.Flag(
			"web.config",
			"[EXPERIMENTAL] Path to config yaml file that can enable TLS or authentication.",
		).Default("").String()
	)

	promlogConfig := &promlog.Config{}
	flag.AddFlags(kingpin.CommandLine, promlogConfig)
	kingpin.Version(version.Print("node_exporter"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()
	logger := promlog.New(promlogConfig)

	if os.Getenv("ON_CONFIGURE") == "1" {
		err := configure()
		if err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}

	err := ini.MapTo(cfg, *configPath)
	if err != nil {
		log.Fatal(fmt.Sprintf("Load config file %s failed: %s", *configPath, err.Error()))
	}

	log.Infoln("Starting node_exporter", version.Info())
	log.Infoln("Build context", version.BuildContext())

	// set flags for exporter_shared server
	flag.Set("web.ssl-cert-file", lookupConfig("web.ssl-cert-file", "").(string))
	flag.Set("web.ssl-key-file", lookupConfig("web.ssl-key-file", "").(string))
	flag.Set("web.auth-file", lookupConfig("web.auth-file", "/opt/ss/ssm-client/ssm.yml").(string))

	if lookupConfig("collectors.print", *printCollectors).(bool) {
		collectorNames := make(sort.StringSlice, 0, len(collector.Factories))
		for n := range collector.Factories {
			collectorNames = append(collectorNames, n)
		}
		collectorNames.Sort()
		fmt.Printf("Available collectors:\n")
		for _, n := range collectorNames {
			fmt.Printf(" - %s\n", n)
		}
		return
	}
	collectors, err := loadCollectors(lookupConfig("collectors.enabled", *enabledCollectors).(string))
	// This instance is only used to check collector creation and logging.
	nc, err := collector.NewNodeCollector()
	if err != nil {
		log.Fatalf("Couldn't create collector: %s", err)
	}
	log.Infof("Enabled collectors:")
	collectors := []string{}
	for n := range nc.Collectors {
		collectors = append(collectors, n)
	}
	sort.Strings(collectors)
	for _, n := range collectors {
		log.Infof(" - %s", n)
	}

	if *disableDefaultCollectors {
		collector.DisableDefaultCollectors()
	}
	level.Info(logger).Log("msg", "Starting node_exporter", "version", version.Info())
	level.Info(logger).Log("msg", "Build context", "build_context", version.BuildContext())
	if user, err := user.Current(); err == nil && user.Uid == "0" {
		level.Warn(logger).Log("msg", "Node Exporter is running as root user. This exporter is designed to run as unpriviledged user, root is not required.")
	}

	http.Handle(*metricsPath, newHandler(!*disableExporterMetrics, *maxRequests, logger))
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
			<head><title>Node Exporter</title></head>
			<body>
			<h1>Node Exporter</h1>
			<p><a href="` + metricsP + `">Metrics</a></p>
			</body>
			</html>`))
	})

	level.Info(logger).Log("msg", "Listening on", "address", *listenAddress)
	server := &http.Server{Addr: *listenAddress}
	if err := web.ListenAndServe(server, *configFile, logger); err != nil {
		level.Error(logger).Log("err", err)
		os.Exit(1)
	}
}

type config struct {
	WebConfig        webConfig        `ini:"web"`
	CollectorsConfig collectorsConfig `ini:"collectors"`
}

type webConfig struct {
	ListenAddress string  `ini:"listen-address"`
	MetricsPath   string  `ini:"telemetry-path"`
	SSLCertFile   string  `ini:"ssl-cert-file"`
	SSLKeyFile    string  `ini:"ssl-key-file"`
	AuthFile      *string `ini:"auth-file"`
}

type collectorsConfig struct {
	Enabled string `ini:"enabled"`
	Print   bool   `ini:"print"`
}

// lookupConfig lookup config from flag
// or config by name, returns nil if none exists.
// name should be in this format -> '[section].[key]'
func lookupConfig(name string, defaultValue interface{}) interface{} {
	flagSet, flagValue := lookupFlag(name)
	if flagSet {
		return flagValue
	}

	section := ""
	key := name
	if i := strings.Index(name, "."); i > 0 {
		section = name[0:i]
		if len(name) > i+1 {
			key = name[i+1:]
		} else {
			key = ""
		}
	}

	t := reflect.TypeOf(*cfg)
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		iniName := field.Tag.Get("ini")
		matched := iniName == section
		if section == "" {
			matched = iniName == key
		}
		if !matched {
			continue
		}

		v := reflect.ValueOf(cfg).Elem().Field(i)
		if section == "" {
			return v.Interface()
		}

		if !v.CanAddr() {
			continue
		}

		st := reflect.TypeOf(v.Interface())
		for j := 0; j < st.NumField(); j++ {
			sectionField := st.Field(j)
			sectionININame := sectionField.Tag.Get("ini")
			if sectionININame != key {
				continue
			}

			if reflect.ValueOf(v.Addr().Elem().Field(j).Interface()).Kind() != reflect.Ptr {
				return v.Addr().Elem().Field(j).Interface()
			}

			if v.Addr().Elem().Field(j).IsNil() {
				return defaultValue
			}

			return v.Addr().Elem().Field(j).Elem().Interface()
		}
	}

	return defaultValue
}

func lookupFlag(name string) (flagSet bool, flagValue interface{}) {
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			flagSet = true
			switch reflect.Indirect(reflect.ValueOf(f.Value)).Kind() {
			case reflect.Bool:
				flagValue = reflect.Indirect(reflect.ValueOf(f.Value)).Bool()
			case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
				flagValue = reflect.Indirect(reflect.ValueOf(f.Value)).Int()
			case reflect.Float32, reflect.Float64:
				flagValue = reflect.Indirect(reflect.ValueOf(f.Value)).Float()
			case reflect.String:
				flagValue = reflect.Indirect(reflect.ValueOf(f.Value)).String()
			case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
				flagValue = reflect.Indirect(reflect.ValueOf(f.Value)).Uint()
			}
		}
	})

	return
}

func configure() error {
	iniCfg, err := ini.Load(*configPath)
	if err != nil {
		return err
	}

	if err = iniCfg.MapTo(cfg); err != nil {
		return err
	}

	type item struct {
		value   reflect.Value
		section string
	}

	items := []item{
		{
			value:   reflect.ValueOf(cfg).Elem(),
			section: "",
		},
	}
	for i := 0; i < len(items); i++ {
		for j := 0; j < items[i].value.Type().NumField(); j++ {
			fieldValue := items[i].value.Field(j)
			fieldType := items[i].value.Type().Field(j)
			section := items[i].section
			key := fieldType.Tag.Get("ini")

			if fieldValue.Kind() == reflect.Struct {
				if fieldValue.CanAddr() && section == "" {
					items = append(items, item{
						value:   fieldValue.Addr().Elem(),
						section: key,
					})
				}
				continue
			}

			flagSet, flagValue := lookupFlag(fmt.Sprintf("%s.%s", section, key))
			if !flagSet {
				continue
			}

			if fieldValue.IsValid() && fieldValue.CanSet() {
				switch fieldValue.Kind() {
				case reflect.Bool:
					iniCfg.Section(section).Key(key).SetValue(fmt.Sprintf("%t", flagValue.(bool)))
				case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
					iniCfg.Section(section).Key(key).SetValue(fmt.Sprintf("%d", flagValue.(int64)))
				case reflect.Float32, reflect.Float64:
					iniCfg.Section(section).Key(key).SetValue(fmt.Sprintf("%f", flagValue.(float64)))
				case reflect.String:
					iniCfg.Section(section).Key(key).SetValue(strconv.Quote(flagValue.(string)))
				case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
					iniCfg.Section(section).Key(key).SetValue(fmt.Sprintf("%d", flagValue.(uint64)))
				}
			}
		}
	}

	if err = iniCfg.SaveTo(*configPath); err != nil {
		return err
	}

	return nil
}
