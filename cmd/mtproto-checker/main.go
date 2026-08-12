package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/yzewe/mtproto-checker/internal/checker"
	"github.com/yzewe/mtproto-checker/internal/filter"
	"github.com/yzewe/mtproto-checker/internal/geo"
	"github.com/yzewe/mtproto-checker/internal/input"
	"github.com/yzewe/mtproto-checker/internal/mtproto"
	"github.com/yzewe/mtproto-checker/internal/report"
)

var version = "dev"

type config struct {
	files        multiFlag
	urls         multiFlag
	stdin        bool
	timeout      time.Duration
	concurrency  int
	attempts     int
	minSuccesses int
	format       string
	out          string
	saveLive     string
	saveDead     string
	saveLinks    string
	aliveOnly    bool
	info         bool
	full         bool
	pings        int
	retryDelay   time.Duration
	apiID        int
	inspect      bool
	speedtest    bool
	hold         time.Duration
	masking      bool
	openCheck    bool
	maxConns     int
	excludes     multiFlag
	modes        string
	ports        string
	countries    string
	asns         string
	sortLatency  bool
	top          int
	noColor      bool
	quiet        bool
	showVersion  bool
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		if errors.Is(err, errNoLiveProxies) {
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
}

var errNoLiveProxies = errors.New("no live proxies")

func run(argv []string) error {
	cfg, args, err := parseFlags(argv)
	if err != nil {
		return err
	}
	if cfg.showVersion {
		fmt.Println("mtproto-checker", version)
		return nil
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	links, err := input.Collect(ctx, input.Sources{
		Args:  args,
		Files: cfg.files,
		URLs:  cfg.urls,
		Stdin: cfg.stdin,
	}, cfg.timeout)
	if err != nil {
		return err
	}
	if len(links) == 0 {
		return errors.New("nothing to check: pass links, --file, --url or --stdin")
	}

	spec, err := buildFilter(cfg)
	if err != nil {
		return err
	}
	links = spec.Links(links)
	if len(links) == 0 {
		return errors.New("every link was filtered out")
	}

	style := report.Style{
		Color:   !cfg.noColor && isTerminal(os.Stdout),
		Verbose: cfg.info || cfg.inspect || cfg.speedtest || cfg.masking || cfg.openCheck || cfg.hold > 0 || cfg.maxConns > 0,
	}

	opts := checker.Options{
		Timeout:      cfg.timeout,
		Concurrency:  cfg.concurrency,
		Attempts:     cfg.attempts,
		MinSuccesses: cfg.minSuccesses,
		Geo:          cfg.info || spec.NeedsGeo(),
		Pings:        cfg.pings,
		RetryDelay:   cfg.retryDelay,
	}
	if cfg.full || cfg.inspect || cfg.speedtest || cfg.hold > 0 {
		opts.Depth = mtproto.DepthFull
	}
	opts.APIID = cfg.apiID
	opts.Inspect = cfg.inspect
	opts.Speedtest = cfg.speedtest
	opts.Hold = cfg.hold
	opts.Masking = cfg.masking
	opts.OpenCheck = cfg.openCheck
	opts.MaxConns = cfg.maxConns
	if opts.Geo {
		opts.Lookup = geo.NewClient(cfg.timeout)
	}
	if progress := newProgress(len(links), cfg); progress != nil {
		opts.OnResult = progress
	}

	started := time.Now()
	results := checker.Run(ctx, links, opts)
	elapsed := time.Since(started)
	clearProgress(cfg)

	if cfg.sortLatency {
		checker.SortByLatency(results)
	}
	results = spec.Results(results)
	shown := results
	if cfg.aliveOnly {
		shown = report.Filter(results, checker.Result.Live)
	}
	if cfg.top > 0 && len(shown) > cfg.top {
		shown = shown[:cfg.top]
	}

	if err := emit(cfg, style, shown, results, elapsed); err != nil {
		return err
	}
	if checker.Summarize(results).Live == 0 {
		return errNoLiveProxies
	}
	return nil
}

func emit(cfg config, style report.Style, shown, all []checker.Result, elapsed time.Duration) error {
	switch cfg.format {
	case "text":
		if !cfg.quiet {
			style.Text(os.Stdout, shown)
			style.Summary(os.Stdout, all, elapsed)
			style.Breakdown(os.Stdout, all, 6)
			style.Best(os.Stdout, all)
		}
	case "json":
		if err := report.JSON(os.Stdout, shown); err != nil {
			return err
		}
	case "csv":
		if err := report.CSV(os.Stdout, shown); err != nil {
			return err
		}
	case "links":
		if err := report.Links(os.Stdout, shown); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown --format %q (want text, json, csv or links)", cfg.format)
	}

	live := report.Filter(all, checker.Result.Live)
	dead := report.Filter(all, func(r checker.Result) bool { return !r.Live() })

	saves := []struct {
		path    string
		results []checker.Result
		write   report.Writer
	}{
		{cfg.out, shown, writerFor(cfg.out)},
		{cfg.saveLive, live, report.JSON},
		{cfg.saveDead, dead, report.JSON},
		{cfg.saveLinks, live, report.Links},
	}
	for _, save := range saves {
		if save.path == "" {
			continue
		}
		if err := report.ToFile(save.path, save.results, save.write); err != nil {
			return fmt.Errorf("saving %s: %w", save.path, err)
		}
		if cfg.format == "text" && !cfg.quiet {
			fmt.Fprintf(os.Stderr, "saved %d results to %s\n", len(save.results), save.path)
		}
	}
	return nil
}

func writerFor(path string) report.Writer {
	switch {
	case strings.HasSuffix(path, ".csv"):
		return report.CSV
	case strings.HasSuffix(path, ".txt"):
		return report.Links
	default:
		return report.JSON
	}
}

func newProgress(total int, cfg config) func(checker.Result) {
	if cfg.quiet || cfg.format != "text" || !isTerminal(os.Stderr) || total < 2 {
		return nil
	}
	var done, live atomic.Int64
	return func(r checker.Result) {
		n := done.Add(1)
		if r.Live() {
			live.Add(1)
		}
		fmt.Fprintf(os.Stderr, "\rchecking %d/%d (%d live)\033[K", n, total, live.Load())
	}
}

func clearProgress(cfg config) {
	if cfg.quiet || cfg.format != "text" || !isTerminal(os.Stderr) {
		return
	}
	fmt.Fprint(os.Stderr, "\r\033[K")
}

func parseFlags(argv []string) (config, []string, error) {
	var cfg config
	fs := flag.NewFlagSet("mtproto-checker", flag.ContinueOnError)

	fs.Var(&cfg.files, "file", "read links from a file (repeatable)")
	fs.Var(&cfg.urls, "url", "read links from an HTTP(S) subscription URL (repeatable)")
	fs.BoolVar(&cfg.stdin, "stdin", false, "read links from stdin")
	fs.DurationVar(&cfg.timeout, "timeout", 8*time.Second, "per-connection timeout")
	fs.IntVar(&cfg.concurrency, "concurrency", 32, "how many proxies to check at once")
	fs.IntVar(&cfg.attempts, "attempts", 2, "probe attempts per proxy")
	fs.IntVar(&cfg.minSuccesses, "min-successes", 1, "successful attempts required to call a proxy live")
	fs.StringVar(&cfg.format, "format", "text", "output format: text, json, csv or links")
	fs.StringVar(&cfg.out, "out", "", "write shown results to a file (.json, .csv or .txt)")
	fs.StringVar(&cfg.saveLive, "save-live", "", "write live results as JSON to a file")
	fs.StringVar(&cfg.saveDead, "save-dead", "", "write dead results as JSON to a file")
	fs.StringVar(&cfg.saveLinks, "save-links", "", "write live proxies as tg:// links to a file")
	fs.BoolVar(&cfg.aliveOnly, "alive-only", false, "show only live proxies")
	fs.BoolVar(&cfg.full, "full", false, "run the complete client handshake: Diffie-Hellman, auth key and encrypted pings")
	fs.IntVar(&cfg.apiID, "api-id", 0, "Telegram api_id from my.telegram.org, required by --inspect and --speedtest")
	fs.BoolVar(&cfg.inspect, "inspect", false, "ask Telegram for the exit country and the datacenter list (implies --full)")
	fs.BoolVar(&cfg.speedtest, "speedtest", false, "measure download speed through the proxy (implies --full)")
	fs.DurationVar(&cfg.hold, "hold", 0, "keep the session alive this long and report drops and latency drift (implies --full)")
	fs.BoolVar(&cfg.masking, "masking", false, "check what a FakeTLS proxy shows to an ordinary TLS client")
	fs.BoolVar(&cfg.openCheck, "check-open", false, "check whether the proxy accepts a wrong secret")
	fs.IntVar(&cfg.maxConns, "max-conns", 0, "open N connections at once to see how many the proxy serves")
	fs.IntVar(&cfg.pings, "pings", mtproto.DefaultPings, "encrypted pings per proxy in --full mode, for jitter and loss")
	fs.DurationVar(&cfg.retryDelay, "retry-delay", 250*time.Millisecond, "wait before the second attempt; later attempts back off")
	fs.Var(&cfg.excludes, "exclude", "skip links or hosts listed in a file (repeatable)")
	fs.StringVar(&cfg.modes, "mode", "", "keep only these kinds: fake_tls, secure, plain, socks5, tcp")
	fs.StringVar(&cfg.ports, "port", "", "keep only these ports, comma separated")
	fs.StringVar(&cfg.countries, "country", "", "keep only these country codes (implies --info)")
	fs.StringVar(&cfg.asns, "asn", "", "keep only these autonomous systems (implies --info)")
	fs.BoolVar(&cfg.info, "info", false, "add secret details and ipwho.is geo data")
	fs.BoolVar(&cfg.sortLatency, "sort", false, "sort live proxies by latency")
	fs.IntVar(&cfg.top, "top", 0, "show only the first N results after sorting")
	fs.BoolVar(&cfg.noColor, "no-color", false, "disable coloured output")
	fs.BoolVar(&cfg.quiet, "quiet", false, "suppress text output, keep files and exit code")
	fs.BoolVar(&cfg.showVersion, "version", false, "print version and exit")

	fs.Usage = func() {
		out := fs.Output()
		fmt.Fprintf(out, "mtproto-checker — check Telegram MTProto, FakeTLS and SOCKS5 proxies.\n\n")
		fmt.Fprintf(out, "Usage:\n  mtproto-checker [flags] [link ...]\n\nFlags:\n")
		fs.PrintDefaults()
		fmt.Fprintf(out, "\nExamples:\n")
		fmt.Fprintf(out, "  mtproto-checker \"tg://proxy?server=1.2.3.4&port=443&secret=ee...\"\n")
		fmt.Fprintf(out, "  mtproto-checker --file proxies.txt --info --sort --alive-only\n")
		fmt.Fprintf(out, "  mtproto-checker --file proxies.txt --full --sort --out results.json\n")
		fmt.Fprintf(out, "  mtproto-checker --url https://t.me/s/channel --country nl,de --alive-only\n")
	}

	if err := fs.Parse(argv); err != nil {
		return cfg, nil, err
	}
	if cfg.attempts < 1 {
		return cfg, nil, errors.New("--attempts must be at least 1")
	}
	if cfg.minSuccesses > cfg.attempts {
		return cfg, nil, errors.New("--min-successes cannot exceed --attempts")
	}
	if (cfg.inspect || cfg.speedtest) && cfg.apiID == 0 {
		return cfg, nil, errors.New("--inspect and --speedtest need --api-id: get one at https://my.telegram.org")
	}
	return cfg, fs.Args(), nil
}

func buildFilter(cfg config) (filter.Spec, error) {
	spec := filter.Spec{
		Modes:     filter.ParseList(cfg.modes),
		Countries: filter.ParseList(cfg.countries),
	}

	ports, err := filter.ParseInts(cfg.ports)
	if err != nil {
		return spec, fmt.Errorf("--port: %w", err)
	}
	spec.Ports = ports

	asns, err := filter.ParseInts(cfg.asns)
	if err != nil {
		return spec, fmt.Errorf("--asn: %w", err)
	}
	spec.ASNs = asns

	var lines []string
	for _, path := range cfg.excludes {
		content, err := os.ReadFile(path)
		if err != nil {
			return spec, err
		}
		lines = append(lines, strings.Split(string(content), "\n")...)
	}
	if len(lines) > 0 {
		spec.Exclude = filter.LoadExclusions(lines)
	}
	return spec, nil
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
