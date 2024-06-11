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
	"crypto/tls"
	"fmt"
	stdlog "log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/user"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/prometheus/common/promlog"
	"github.com/prometheus/common/promlog/flag"
	"golang.org/x/crypto/bcrypt"

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

func setByUserFlagAction() func(ctx *kingpin.ParseContext) error {
	executed := false

	return func(pc *kingpin.ParseContext) error {
		if executed {
			return nil
		}

		for _, elem := range pc.Elements {
			if elem.Clause == nil {
				continue
			}

			flagClause, ok := elem.Clause.(*kingpin.FlagClause)
			if !ok || flagClause == nil {
				continue
			}

			setByUserMap[flagClause.Model().Name] = true
		}

		executed = true
		return nil
	}
}

// this function is for translating single-hyphen flags into long flags,
// to make it compatible with earily PMM/SSM version of node_exporter
func convertFlagAction(short rune) func(ctx *kingpin.ParseContext) error {
	convertedMap := make(map[rune]bool)

	return func(pc *kingpin.ParseContext) error {
		if convertedMap[short] {
			return nil
		}

		for _, elem := range pc.Elements {
			if elem.Clause == nil {
				continue
			}

			flagClause, ok := elem.Clause.(*kingpin.FlagClause)
			if !ok || flagClause.Hidden().Model().Short != short {
				continue
			}

			ctx, err := kingpin.CommandLine.ParseContext([]string{fmt.Sprintf("--%c%s", short, *elem.Value)})
			if err != nil && ctx != nil && len(ctx.Elements) > 0 && ctx.Elements[0].Clause != nil {
				// with standard flag package, single-hyphen bool flag is in format
				// '-<name>=<bool>', this code block here tries to translate it into
				// kingpin long bool flag

				clause, ok := ctx.Elements[0].Clause.(*kingpin.FlagClause)
				if !ok || !clause.Model().IsBoolFlag() {
					return err
				}

				boolStrs := strings.Split(*elem.Value, "=")
				if len(boolStrs) == 1 {
					return err
				}

				var boolValue bool
				boolValue, err = strconv.ParseBool(boolStrs[len(boolStrs)-1])
				if err != nil {
					return err
				}

				if boolValue {
					ctx, err = kingpin.CommandLine.ParseContext([]string{fmt.Sprintf("--%s", clause.Model().Name)})
				} else {
					ctx, err = kingpin.CommandLine.ParseContext([]string{fmt.Sprintf("--no-%s", clause.Model().Name)})
				}
			}
			if err != nil || ctx == nil || len(ctx.Elements) == 0 || ctx.Elements[0].Clause == nil {
				return err
			}

			flag, ok := ctx.Elements[0].Clause.(*kingpin.FlagClause)
			if !ok {
				return fmt.Errorf("unknow flag")
			}

			setByUserMap[flag.Model().Name] = true
			if err = flag.Model().Value.Set(*ctx.Elements[0].Value); err != nil {
				return err
			}
		}

		convertedMap[short] = true
		return nil
	}
}

const webAuthFileFlagName = "web.auth-file"

var (
	disableDefaultCollectors = kingpin.Flag(
		"collector.disable-defaults",
		"Set all collectors to disabled by default.",
	).Default("false").Bool()
	maxProcs = kingpin.Flag(
		"runtime.gomaxprocs", "The target number of CPUs Go will run on (GOMAXPROCS)",
	).Envar("GOMAXPROCS").Default("1").Int()
	disableExporterMetrics = kingpin.Flag(
		"web.disable-exporter-metrics",
		"Exclude metrics about the exporter itself (promhttp_*, process_*, go_*).",
	).Bool()
	maxRequests = kingpin.Flag(
		"web.max-requests",
		"Maximum number of parallel scrape requests. Use 0 to disable.",
	).Default("40").Int()
	metricsPath = kingpin.Flag(
		"web.telemetry-path",
		"Path under which to expose metrics.",
	).Default("/metrics").String()
	configPath = kingpin.Flag(
		"config",
		"Path of config file",
	).Default("/opt/ss/ssm-client/node_exporter.conf").String()
	listenAddress = kingpin.Flag(
		"web.listen-address",
		"Address on which to expose metrics and web interface.",
	).Strings()
	enabledCollectors = kingpin.Flag(
		"collectors.enabled",
		"Comma-separated list of collectors to use.",
	).String()
	printCollectors = kingpin.Flag(
		"collectors.print",
		"If true, print available collectors and exit.",
	).Bool()
	sslCertFile = kingpin.Flag(
		"web.ssl-cert-file",
		"Path to SSL certificate file.",
	).String()
	sslKeyFile = kingpin.Flag(
		"web.ssl-key-file",
		"Path to SSL key file.",
	).String()
	webAuthFile = kingpin.Flag(
		webAuthFileFlagName,
		"Path to YAML file with server_user, server_password keys for HTTP Basic authentication.",
	).String()
	webConfigFile = kingpin.Flag(
		"web.config.file",
		"Path to prometheus web config file (YAML).",
	).Default("/opt/ss/ssm-client/node_exporter.yml").String()
	systemdSocket = kingpin.Flag(
		"web.systemd-socket",
		"Use systemd socket activation listeners instead of port listeners (Linux only).",
	).Bool()
	promlogConfig = &promlog.Config{
		Level:  &promlog.AllowedLevel{},
		Format: &promlog.AllowedFormat{},
	}

	_ = kingpin.Flag("c", "").Hidden().Short('c').Action(convertFlagAction('c')).Strings()
	_ = kingpin.Flag("w", "").Hidden().Short('w').Action(convertFlagAction('w')).Strings()
)

func init() {
	kingpin.Flag(flag.LevelFlagName, flag.LevelFlagHelp).
		Default("info").SetValue(promlogConfig.Level)
	kingpin.Flag(flag.FormatFlagName, flag.FormatFlagHelp).
		Default("logfmt").SetValue(promlogConfig.Format)

	kingpin.CommandLine.PreAction(setByUserFlagAction())
}

func main() {
	kingpin.Version(version.Print("node_exporter"))
	kingpin.CommandLine.UsageWriter(os.Stdout)
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()

	if err := ini.MapTo(&cfg, *configPath); err != nil {
		stdlog.Fatalf(fmt.Sprintf("Load config file %s failed: %s\n", *configPath, err.Error()))
	}

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

	var authC authConfig
	if *webAuthFile != "" {
		authConfigBytes, err := os.ReadFile(*webAuthFile)
		if err != nil {
			level.Error(logger).Log("err", err)
			os.Exit(1)
		}
		if err := yaml.Unmarshal(authConfigBytes, &authC); err != nil {
			level.Error(logger).Log("err", err)
			os.Exit(1)
		}
	}

	tlsMinVer := (web.TLSVersion)(tls.VersionTLS10)
	tlsMaxVer := (web.TLSVersion)(tls.VersionTLS13)

	prometheusWebConfig := prometheusWebConfig{
		TLSConfig: tlsConfig{
			MinVersion: &tlsMinVer,
			MaxVersion: &tlsMaxVer,
		},
	}
	if authC.ServerUser != "" {
		hashedPsw, err := bcrypt.GenerateFromPassword([]byte(authC.ServerPassword), 0)
		if err != nil {
			level.Error(logger).Log("err", err)
			os.Exit(1)
		}
		prometheusWebConfig.Users = map[string]string{
			authC.ServerUser: string(hashedPsw),
		}
	}
	if *sslCertFile != "" || *sslKeyFile != "" {
		prometheusWebConfig.TLSConfig.TLSCertPath = *sslCertFile
		prometheusWebConfig.TLSConfig.TLSKeyPath = *sslKeyFile
	}

	if *webConfigFile == "" {
		level.Error(logger).Log("Use web.config.file flag/config to tell the location of prometheus web file")
		os.Exit(1)
	}
	webConfigBytes, err := yaml.Marshal(prometheusWebConfig)
	if err != nil {
		level.Error(logger).Log("err", err)
		os.Exit(1)
	}
	if err = os.WriteFile(*webConfigFile, webConfigBytes, 0600); err != nil {
		level.Error(logger).Log("err", err)
		os.Exit(1)
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
	Log        logConfig        `ini:"log"`
}

type webConfig struct {
	ListenAddress          []string `ini:"listen-address"`
	TelemetryPath          string   `ini:"telemetry-path" help:"Path under which to expose metrics."`
	SSLCertFile            string   `ini:"ssl-cert-file"`
	SSLKeyFile             string   `ini:"ssl-key-file"`
	AuthFile               string   `ini:"auth-file"`
	ConfigFile             *string  `ini:"config.file"`
	DisableExporterMetrics bool     `ini:"disable-exporter-metrics" help:"Exclude metrics about the exporter itself (promhttp_*, process_*, go_*)."`
	MaxRequests            int      `ini:"max-requests" help:"Maximum number of parallel scrape requests. Use 0 to disable."`
	SystemdSocket          bool     `ini:"systemd-socket"`
}

type collectorsConfig struct {
	Enabled string `ini:"enabled"`
	Print   bool   `ini:"print"`
}

type collectorConfig struct {
	DisableDefaults                    bool `ini:"disable-defaults"`
	collector.ARPConfig                `ini:"collector"`
	collector.BCacheConfig             `ini:"collector"`
	collector.BondingConfig            `ini:"collector"`
	collector.BtrfsConfig              `ini:"collector"`
	collector.BuddyInfoConfig          `ini:"collector"`
	collector.CGroupsConfig            `ini:"collector"`
	collector.ConntrackConfig          `ini:"collector"`
	collector.CPUConfig                `ini:"collector"`
	collector.CPUVulnerabilitiesConfig `ini:"collector"`
	collector.CPUFreqConfig            `ini:"collector"`
	collector.DiskStatsConfig          `ini:"collector"`
	collector.DMIConfig                `ini:"collector"`
	collector.DrbdConfig               `ini:"collector"`
	collector.DRMConfig                `ini:"collector"`
	collector.EDACConfig               `ini:"collector"`
	collector.EntropyConfig            `ini:"collector"`
	collector.EthtoolConfig            `ini:"collector"`
	collector.FibreChannelConfig       `ini:"collector"`
	collector.FilefdConfig             `ini:"collector"`
	collector.FilesystemConfig         `ini:"collector"`
	collector.HWmonConfig              `ini:"collector"`
	collector.InfinibandConfig         `ini:"collector"`
	collector.InterruptsConfig         `ini:"collector"`
	collector.IPVSConfig               `ini:"collector"`
	collector.KSMDConfig               `ini:"collector"`
	collector.LnStatConfig             `ini:"collector"`
	collector.LoadavgConfig            `ini:"collector"`
	collector.LogindConfig             `ini:"collector"`
	collector.MdadmConfig              `ini:"collector"`
	collector.MeminfoConfig            `ini:"collector"`
	collector.MeminfoNumaConfig        `ini:"collector"`
	collector.MountStatsConfig         `ini:"collector"`
	collector.NetClassConfig           `ini:"collector"`
	collector.NetDevConfig             `ini:"collector"`
	collector.NetStatConfig            `ini:"collector"`
	collector.NetworkRouteConfig       `ini:"collector"`
	collector.NFSConfig                `ini:"collector"`
	collector.NFSDConfig               `ini:"collector"`
	collector.NTPConfig                `ini:"collector"`
	collector.NVMEConfig               `ini:"collector"`
	collector.OSConfig                 `ini:"collector"`
	collector.PathConfig               `ini:"collector"`
	collector.PerfConfig               `ini:"collector"`
	collector.PowerSupplyConfig        `ini:"collector"`
	collector.PressureConfig           `ini:"collector"`
	collector.ProcessesConfig          `ini:"collector"`
	collector.QdiscConfig              `ini:"collector"`
	collector.RaplConfig               `ini:"collector"`
	collector.RunitConfig              `ini:"collector"`
	collector.SchedStatConfig          `ini:"collector"`
	collector.SELinuxConfig            `ini:"collector"`
	collector.SlabInfoConfig           `ini:"collector"`
	collector.SockStatConfig           `ini:"collector"`
	collector.SoftirqsConfig           `ini:"collector"`
	collector.SoftNetConfig            `ini:"collector"`
	collector.StatConfig               `ini:"collector"`
	collector.SupervisorConfig         `ini:"collector"`
	collector.SysctlConfig             `ini:"collector"`
	collector.SystemdConfig            `ini:"collector"`
	collector.TapeStatsConfig          `ini:"collector"`
	collector.TCPStatConfig            `ini:"collector"`
	collector.TextFileConfig           `ini:"collector"`
	collector.ThermalZoneConfig        `ini:"collector"`
	collector.TimeConfig               `ini:"collector"`
	collector.TimexConfig              `ini:"collector"`
	collector.UDPQueuesConfig          `ini:"collector"`
	collector.UnameConfig              `ini:"collector"`
	collector.VMStatConfig             `ini:"collector"`
	collector.WIFIConfig               `ini:"collector"`
	collector.XFSConfig                `ini:"collector"`
	collector.ZFSConfig                `ini:"collector"`
	collector.ZoneInfoConfig           `ini:"collector"`
}

type runtimeConfig struct {
	GoMaxProcs int `ini:"gomaxprocs"`
}

type logConfig struct {
	Level  promlog.AllowedLevel  `ini:"level"`
	Format promlog.AllowedFormat `ini:"format"`
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
			key := strings.SplitN(fieldType.Tag.Get("ini"), ",", 2)[0]

			if fieldValue.Kind() == reflect.Struct {
				if fieldValue.CanAddr() {
					if section == "" {
						section = key
					} else if section != key {
						section = fmt.Sprintf("%s.%s", section, key)
					}

					items = append(items, item{
						value:   fieldValue.Addr().Elem(),
						section: section,
					})
				}
				continue
			} else if fieldValue.Kind() == reflect.Ptr && fieldValue.Type().Elem().Kind() == reflect.String && fieldValue.IsNil() {
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

		// Don't override web.auth-file config
		if flagKey == webAuthFileFlagName {
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

		var values []reflect.Value
		if fieldValue.Kind() == reflect.Slice {
			for i := 0; i < fieldValue.Len(); i++ {
				values = append(values, fieldValue.Index(i))
			}
		} else {
			values = []reflect.Value{fieldValue}
		}

		for i := range values {
			switch values[i].Kind() {
			case reflect.Int, reflect.Int8, reflect.Int16, reflect.Float32, reflect.Int64:
				kingpinF.Model().Value.Set(strconv.FormatInt(values[i].Int(), 10))
			case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
				kingpinF.Model().Value.Set(strconv.FormatUint(values[i].Uint(), 10))
			case reflect.Bool:
				kingpinF.Model().Value.Set(strconv.FormatBool(values[i].Bool()))
			default:
				kingpinF.Model().Value.Set(values[i].String())
			}
		}
	})
}

type authConfig struct {
	ServerUser     string `yaml:"server_user,omitempty"`
	ServerPassword string `yaml:"server_password,omitempty"`
}

type prometheusWebConfig struct {
	TLSConfig tlsConfig         `yaml:"tls_server_config"`
	Users     map[string]string `yaml:"basic_auth_users"`
}

type tlsConfig struct {
	TLSCertPath string          `yaml:"cert_file"`
	TLSKeyPath  string          `yaml:"key_file"`
	MinVersion  *web.TLSVersion `yaml:"min_version"`
	MaxVersion  *web.TLSVersion `yaml:"max_version"`
}
