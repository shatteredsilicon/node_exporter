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
	"fmt"
	stdlog "log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/user"
	"reflect"
	"runtime"
	"sort"
	"strings"

	prometheusConfig "github.com/prometheus/common/config"
	"github.com/prometheus/common/promlog"
	"github.com/prometheus/common/promlog/flag"

	"github.com/alecthomas/kingpin/v2"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	promcollectors "github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/version"
	"github.com/prometheus/exporter-toolkit/web"
	"github.com/shatteredsilicon/node_exporter/collector"
	"gopkg.in/ini.v1"
	"gopkg.in/yaml.v2"
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

func newHandler(includeExporterMetrics bool, maxRequests int, logger log.Logger) *handler {
	h := &handler{
		exporterMetricsRegistry: prometheus.NewRegistry(),
		includeExporterMetrics:  includeExporterMetrics,
		maxRequests:             maxRequests,
		logger:                  logger,
	}
	if h.includeExporterMetrics {
		h.exporterMetricsRegistry.MustRegister(
			promcollectors.NewProcessCollector(promcollectors.ProcessCollectorOpts{}),
			promcollectors.NewGoCollector(),
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

	var handler http.Handler
	if h.includeExporterMetrics {
		handler = promhttp.HandlerFor(
			prometheus.Gatherers{h.exporterMetricsRegistry, r},
			promhttp.HandlerOpts{
				ErrorLog:            stdlog.New(log.NewStdlibAdapter(level.Error(h.logger)), "", 0),
				ErrorHandling:       promhttp.ContinueOnError,
				MaxRequestsInFlight: h.maxRequests,
				Registry:            h.exporterMetricsRegistry,
			},
		)
		// Note that we have to use h.exporterMetricsRegistry here to
		// use the same promhttp metrics for all expositions.
		handler = promhttp.InstrumentMetricHandler(
			h.exporterMetricsRegistry, handler,
		)
	} else {
		handler = promhttp.HandlerFor(
			r,
			promhttp.HandlerOpts{
				ErrorLog:            stdlog.New(log.NewStdlibAdapter(level.Error(h.logger)), "", 0),
				ErrorHandling:       promhttp.ContinueOnError,
				MaxRequestsInFlight: h.maxRequests,
			},
		)
	}

	return handler, nil
}

var cfg = new(config)
var setByUserMap = make(map[string]bool)

func flagAction(flagName string) func(ctx *kingpin.ParseContext) error {
	return func(ctx *kingpin.ParseContext) error {
		setByUserMap[flagName] = true
		return nil
	}
}

var (
	disableDefaultCollectors = kingpin.Flag(
		"collector.disable-defaults",
		"Set all collectors to disabled by default.",
	).Action(flagAction("collector.disable-defaults")).Bool()
	maxProcs = kingpin.Flag(
		"runtime.gomaxprocs", "The target number of CPUs Go will run on (GOMAXPROCS)",
	).Envar("GOMAXPROCS").Action(flagAction("runtime.gomaxprocs")).Int()
	disableExporterMetrics = kingpin.Flag(
		"web.disable-exporter-metrics",
		"Exclude metrics about the exporter itself (promhttp_*, process_*, go_*).",
	).Action(flagAction("web.disable-exporter-metrics")).Bool()
	maxRequests = kingpin.Flag(
		"web.max-requests",
		"Maximum number of parallel scrape requests. Use 0 to disable.",
	).Action(flagAction("web.max-requests")).Int()
	metricsPath = kingpin.Flag(
		"web.telemetry-path",
		"Path under which to expose metrics.",
	).Action(flagAction("web.telemetry-path")).String()
	configPath = kingpin.Flag(
		"config",
		"Path of config file",
	).Action(flagAction("config")).Default("/opt/ss/ssm-client/node_exporter.conf").String()
	listenAddress = kingpin.Flag(
		"web.listen-address",
		"Address on which to expose metrics and web interface.",
	).Action(flagAction("web.listen-address")).Strings()
	enabledCollectors = kingpin.Flag(
		"collectors.enabled",
		"Comma-separated list of collectors to use.",
	).Action(flagAction("collectors.enabled")).String()
	printCollectors = kingpin.Flag(
		"collectors.print",
		"If true, print available collectors and exit.",
	).Action(flagAction("collectors.print")).Bool()
	sslCertFile = kingpin.Flag(
		"web.ssl-cert-file",
		"Path to SSL certificate file.",
	).Action(flagAction("web.ssl-cert-file")).Default("").String()
	sslKeyFile = kingpin.Flag(
		"web.ssl-key-file",
		"Path to SSL key file.",
	).Action(flagAction("web.ssl-key-file")).String()
	webAuthFile = kingpin.Flag(
		"web.auth-file",
		"Path to YAML file with server_user, server_password keys for HTTP Basic authentication.",
	).Action(flagAction("web.auth-file")).String()
	webConfigFile = kingpin.Flag(
		"web.config.file",
		"Path to prometheus web config file (YAML).",
	).Action(flagAction("web.config.file")).String()
	systemdSocket = kingpin.Flag(
		"web.systemd-socket",
		"Use systemd socket activation listeners instead of port listeners (Linux only).",
	).Action(flagAction("web.systemd-socket")).Bool()
)

func main() {
	kingpin.Parse()

	if err := ini.MapTo(&cfg, *configPath); err != nil {
		stdlog.Fatalf(fmt.Sprintf("Load config file %s failed: %s\n", *configPath, err.Error()))
	}

	promlogConfig := &promlog.Config{}
	flag.AddFlags(kingpin.CommandLine, promlogConfig)
	kingpin.Version(version.Print("node_exporter"))
	kingpin.CommandLine.UsageWriter(os.Stdout)
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()

	if os.Getenv("ON_CONFIGURE") == "1" {
		err := configure()
		if err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}

	// override flag value with config value
	// if it's not set
	overrideFlags()

	if *printCollectors {
		names := collector.Collectors()
		collectorNames := make(sort.StringSlice, 0, len(names))
		copy(collectorNames, names)
		collectorNames.Sort()
		fmt.Printf("Available collectors:\n")
		for _, n := range collectorNames {
			fmt.Printf(" - %s\n", n)
		}
		return
	}

	if *disableDefaultCollectors {
		collector.DisableDefaultCollectors()
	}

	if *enabledCollectors != "" {
		collector.DisableDefaultCollectors()
		for _, name := range strings.Split(*enabledCollectors, ",") {
			collector.SetCollectorState(name, true)
		}
	}

	logger := promlog.New(promlogConfig)

	level.Info(logger).Log("msg", "Starting node_exporter", "version", version.Info())
	level.Info(logger).Log("msg", "Build context", "build_context", version.BuildContext())
	if user, err := user.Current(); err == nil && user.Uid == "0" {
		level.Warn(logger).Log("msg", "Node Exporter is running as root user. This exporter is designed to run as unprivileged user, root is not required.")
	}

	runtime.GOMAXPROCS(*maxProcs)
	level.Debug(logger).Log("msg", "Go MAXPROCS", "procs", runtime.GOMAXPROCS(0))

	http.Handle(*metricsPath, newHandler(!*disableExporterMetrics, *maxRequests, logger))
	if *metricsPath != "/" {
		landingConfig := web.LandingConfig{
			Name:        "Node Exporter",
			Description: "Prometheus Node Exporter",
			Version:     version.Info(),
			Links: []web.LandingLinks{
				{
					Address: *metricsPath,
					Text:    "Metrics",
				},
			},
		}
		landingPage, err := web.NewLandingPage(landingConfig)
		if err != nil {
			level.Error(logger).Log("err", err)
			os.Exit(1)
		}
		http.Handle("/", landingPage)
	}

	if *sslCertFile != "" || *sslKeyFile != "" {
		if *webConfigFile == "" {
			level.Error(logger).Log("Use web.config.file flag/config to tell the location of prometheus web file")
			os.Exit(1)
		}

		authConfigBytes, err := os.ReadFile(*webAuthFile)
		if err != nil {
			level.Error(logger).Log("err", err)
			os.Exit(1)
		}
		var authC authConfig
		if err := yaml.Unmarshal(authConfigBytes, &authC); err != nil {
			level.Error(logger).Log("err", err)
			os.Exit(1)
		}

		prometheusWebConfig := web.Config{
			Users: map[string]prometheusConfig.Secret{
				authC.ServerUser: prometheusConfig.Secret(authC.ServerPassword),
			},
		}
		prometheusWebConfig.TLSConfig.TLSCertPath = *sslCertFile
		prometheusWebConfig.TLSConfig.TLSKeyPath = *sslKeyFile

		webConfigBytes, err := yaml.Marshal(prometheusWebConfig)
		if err != nil {
			level.Error(logger).Log("err", err)
			os.Exit(1)
		}

		if err = os.WriteFile(*webConfigFile, webConfigBytes, 0600); err != nil {
			level.Error(logger).Log("err", err)
			os.Exit(1)
		}
	}

	server := &http.Server{}
	toolkitFlags := &web.FlagConfig{
		WebSystemdSocket:   systemdSocket,
		WebListenAddresses: listenAddress,
		WebConfigFile:      webConfigFile,
	}
	if err := web.ListenAndServe(server, toolkitFlags, logger); err != nil {
		level.Error(logger).Log("err", err)
		os.Exit(1)
	}
}

type config struct {
	Web        webConfig        `ini:"web"`
	Collectors collectorsConfig `ini:"collectors"`
	Collector  collectorConfig  `ini:"collector"`
	Runtime    runtimeConfig    `ini:"runtime"`
}

type webConfig struct {
	ListenAddress          []string `ini:"listen-address"`
	TelemetryPath          string   `ini:"telemetry-path" help:"Path under which to expose metrics."`
	SSLCertFile            string   `ini:"ssl-cert-file"`
	SSLKeyFile             string   `ini:"ssl-key-file"`
	AuthFile               string   `ini:"auth-file"`
	ConfigFile             string   `ini:"config.file"`
	DisableExporterMetrics bool     `ini:"disable-exporter-metrics" help:"Exclude metrics about the exporter itself (promhttp_*, process_*, go_*)."`
	MaxRequests            int      `ini:"max-requests" help:"Maximum number of parallel scrape requests. Use 0 to disable."`
	SystemdSocket          bool     `ini:"systemd-socket"`
}

type collectorsConfig struct {
	Enabled string `ini:"enabled"`
	Print   bool   `ini:"print"`
}

type collectorConfig struct {
	DisableDefaults bool `ini:"disable-defaults"`
}

type runtimeConfig struct {
	GoMaxProcs int `ini:"gomaxprocs"`
}

func configVisit(visitFn func(string, string, reflect.Value)) {
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

			visitFn(section, key, fieldValue)
		}
	}
}

func configure() error {
	iniCfg, err := ini.Load(*configPath)
	if err != nil {
		return err
	}

	if err = iniCfg.MapTo(cfg); err != nil {
		return err
	}

	configVisit(func(section, key string, fieldValue reflect.Value) {
		flagKey := fmt.Sprintf("%s.%s", section, key)
		if section == "" {
			flagKey = key
		}

		setByUser := setByUserMap[flagKey]
		kingpinF := kingpin.CommandLine.GetFlag(flagKey)
		if !setByUser || kingpinF == nil {
			return
		}

		iniCfg.Section(section).Key(key).SetValue(kingpinF.Model().Value.String())
	})

	if err = iniCfg.SaveTo(*configPath); err != nil {
		return err
	}

	return nil
}

func overrideFlags() {
	configVisit(func(section, key string, fieldValue reflect.Value) {
		flagKey := fmt.Sprintf("%s.%s", section, key)
		if section == "" {
			flagKey = key
		}

		setByUser := setByUserMap[flagKey]
		kingpinF := kingpin.CommandLine.GetFlag(flagKey)
		if setByUser || kingpinF == nil {
			return
		}
		if fieldValue.Kind() == reflect.Slice {
			for i := 0; i < fieldValue.Len(); i++ {
				fmt.Printf("key: %s, value: %s\n", flagKey, fieldValue.Index(i).String())
				kingpinF.Model().Value.Set(fieldValue.Index(i).String())
			}
		} else {
			fmt.Printf("key: %s, value: %s\n", flagKey, fieldValue.String())
			kingpinF.Model().Value.Set(fieldValue.String())
		}
	})
}

type authConfig struct {
	ServerUser     string `yaml:"server_user,omitempty"`
	ServerPassword string `yaml:"server_password,omitempty"`
}
