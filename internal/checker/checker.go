package checker

import (
	"context"
	"errors"
	"math"
	mathrand "math/rand/v2"
	"sort"
	"sync"
	"time"

	"github.com/yzewe/mtproto-checker/internal/geo"
	"github.com/yzewe/mtproto-checker/internal/mtproto"
	"github.com/yzewe/mtproto-checker/internal/proxy"
)

type Status string

const (
	StatusLive Status = "live"

	StatusDead Status = "dead"

	StatusInvalid Status = "invalid"
)

type Options struct {
	Timeout      time.Duration
	Concurrency  int
	Attempts     int
	MinSuccesses int

	Depth mtproto.Depth

	Pings int

	RetryDelay time.Duration

	APIID     int
	Inspect   bool
	Speedtest bool
	Hold      time.Duration
	Masking   bool
	OpenCheck bool
	MaxConns  int

	Geo    bool
	Lookup *geo.Client

	OnResult func(Result)
}

func (o Options) Defaults() Options {
	if o.Timeout <= 0 {
		o.Timeout = 10 * time.Second
	}
	if o.Concurrency <= 0 {
		o.Concurrency = 16
	}
	if o.Attempts <= 0 {
		o.Attempts = 2
	}
	if o.MinSuccesses <= 0 {
		o.MinSuccesses = 1
	}
	if o.MinSuccesses > o.Attempts {
		o.MinSuccesses = o.Attempts
	}
	if o.RetryDelay <= 0 {
		o.RetryDelay = 250 * time.Millisecond
	}
	return o
}

type SecretInfo struct {
	Mode   proxy.SecretMode `json:"mode"`
	Domain string           `json:"domain,omitempty"`
	KeyHex string           `json:"key_hex,omitempty"`
	Length int              `json:"length"`
}

type Result struct {
	Input     string         `json:"input"`
	Canonical string         `json:"canonical,omitempty"`
	Host      string         `json:"host,omitempty"`
	Port      int            `json:"port,omitempty"`
	Kind      proxy.Kind     `json:"kind,omitempty"`
	Title     string         `json:"title,omitempty"`
	Status    Status         `json:"status"`
	LatencyMS float64        `json:"latency_ms,omitempty"`
	Route     *mtproto.Route `json:"route,omitempty"`
	Attempts  int            `json:"attempts"`
	Successes int            `json:"successes"`
	Error     string         `json:"error,omitempty"`

	ErrorKind mtproto.Kind            `json:"error_kind,omitempty"`
	Timings   *mtproto.Timings        `json:"timings,omitempty"`
	Ping      *mtproto.PingStats      `json:"ping,omitempty"`
	Nearest   *mtproto.NearestDC      `json:"nearest_dc,omitempty"`
	Config    *mtproto.ConfigInfo     `json:"config,omitempty"`
	Speed     *mtproto.SpeedStats     `json:"speed,omitempty"`
	Stability *mtproto.StabilityStats `json:"stability,omitempty"`
	Audit     *mtproto.Audit          `json:"audit,omitempty"`
	Score     int                     `json:"score,omitempty"`
	Grade     string                  `json:"grade,omitempty"`
	Secret    *SecretInfo             `json:"secret,omitempty"`
	Geo       *geo.Info               `json:"geo,omitempty"`
}

func (r Result) Live() bool { return r.Status == StatusLive }

func Run(ctx context.Context, inputs []string, opts Options) []Result {
	opts = opts.Defaults()

	results := make([]Result, len(inputs))
	jobs := make(chan int)
	var wg sync.WaitGroup

	for range opts.Concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				results[i] = check(ctx, inputs[i], opts)
				if opts.OnResult != nil {
					opts.OnResult(results[i])
				}
			}
		}()
	}

	for i := range inputs {
		select {
		case jobs <- i:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return results
		}
	}
	close(jobs)
	wg.Wait()
	return results
}

func check(ctx context.Context, input string, opts Options) Result {
	target, err := proxy.Parse(input)
	if err != nil {
		return Result{Input: input, Status: StatusInvalid, Error: err.Error()}
	}

	result := Result{
		Input:     input,
		Canonical: target.Canonical(),
		Host:      target.Host,
		Port:      target.Port,
		Kind:      target.Kind,
		Title:     target.Title,
	}
	if target.Kind == proxy.KindMTProto {
		result.Secret = &SecretInfo{
			Mode:   target.Mode(),
			KeyHex: hexString(target.SecretKey()),
			Length: len(target.SecretBytes()),
		}
		if target.Mode() == proxy.ModeFakeTLS {
			result.Secret.Domain = target.SNI()
		}
	}

	probe := mtproto.New(opts.Timeout)
	probe.Depth = opts.Depth
	probe.APIID = opts.APIID
	probe.Inspect = opts.Inspect
	probe.Speedtest = opts.Speedtest
	probe.Hold = opts.Hold
	if opts.Pings > 0 {
		probe.Pings = opts.Pings
	}

	var lastErr error
	best := time.Duration(0)

	for attempt := 1; attempt <= opts.Attempts; attempt++ {
		if attempt > 1 && !sleepBackoff(ctx, opts.RetryDelay, attempt) {
			break
		}
		if ctx.Err() != nil {
			lastErr = ctx.Err()
			break
		}
		result.Attempts = attempt

		attemptCtx, cancel := context.WithTimeout(ctx, probe.TotalBudget())
		started := time.Now()
		outcome, err := probe.Probe(attemptCtx, target)
		elapsed := time.Since(started)
		cancel()

		if err != nil {
			lastErr = err
			var probeErr *mtproto.Error
			if errors.As(err, &probeErr) && probeErr.Stage == mtproto.StageDial {
				break
			}
			continue
		}

		result.Successes++
		if best == 0 || elapsed < best {
			best = elapsed
			route := outcome.Route
			timings := outcome.Timings
			timings.TotalMS = round1(float64(elapsed.Microseconds()) / 1000)
			result.Route = &route
			result.Timings = &timings
			result.Ping = outcome.Ping
			result.Nearest = outcome.Nearest
			result.Config = outcome.Config
			result.Speed = outcome.Speed
			result.Stability = outcome.Stability
		}
		if result.Successes >= opts.MinSuccesses {
			break
		}
	}

	if result.Successes >= opts.MinSuccesses {
		result.Status = StatusLive
		result.LatencyMS = representativeLatency(result, best)
		result.Score, result.Grade = rate(result)
	} else {
		result.Status = StatusDead
		result.Error = errorText(lastErr, opts)
		result.ErrorKind = errorKind(lastErr)
	}

	if opts.Geo && opts.Lookup != nil {
		result.Geo = opts.Lookup.Lookup(ctx, target.Host)
	}
	if audit := runAudit(ctx, probe, target, opts, result); audit != nil {
		result.Audit = audit
	}
	return result
}

// runAudit collects the checks that need their own connections. They are only
// worth doing for a proxy that answered at all.
func runAudit(ctx context.Context, probe *mtproto.Checker, target *proxy.Target, opts Options, result Result) *mtproto.Audit {
	if !result.Live() || (!opts.Masking && !opts.OpenCheck && opts.MaxConns <= 0) {
		return nil
	}

	audit := &mtproto.Audit{}
	if opts.Masking && target.Mode() == proxy.ModeFakeTLS {
		audit.Masking = probe.CheckMasking(ctx, target)
	}
	if opts.OpenCheck && target.Kind == proxy.KindMTProto {
		if open, err := probe.CheckOpenSecret(ctx, target); err == nil {
			audit.AcceptsAnySecret = &open
		}
	}
	if opts.MaxConns > 0 {
		audit.ConnLimit = probe.CheckConnLimit(ctx, target, opts.MaxConns)
	}
	return audit
}

const maxRetryDelay = 2 * time.Second

func sleepBackoff(ctx context.Context, base time.Duration, attempt int) bool {
	delay := maxRetryDelay
	if shift := attempt - 2; shift >= 0 && shift < 32 {
		if scaled := base << shift; scaled > 0 && scaled < delay {
			delay = scaled
		}
	}
	if delay <= 0 {
		delay = time.Millisecond
	}
	delay += time.Duration(mathrand.Int64N(int64(delay/2) + 1))

	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func errorKind(err error) mtproto.Kind {
	if err == nil {
		return mtproto.KindOther
	}
	if errors.Is(err, context.Canceled) {
		return mtproto.KindCanceled
	}
	return mtproto.KindOf(err)
}

func representativeLatency(r Result, total time.Duration) float64 {
	switch {
	case r.Ping != nil && r.Ping.MedianMS > 0:
		return round1(r.Ping.MedianMS)
	case r.Timings != nil && r.Timings.RespQMS > 0:
		return round1(r.Timings.RespQMS)
	default:
		return round1(float64(total.Microseconds()) / 1000)
	}
}

func rate(r Result) (int, string) {
	latency := r.LatencyMS
	if r.Ping != nil && r.Ping.MedianMS > 0 {
		latency = r.Ping.MedianMS
	} else if r.Timings != nil && r.Timings.RespQMS > 0 {
		latency = r.Timings.RespQMS
	}

	score := 100.0
	switch {
	case latency <= 100:
		score = 100
	case latency >= 1000:
		score = 10
	default:
		score = 100 - (latency-100)/900*90
	}

	if r.Ping != nil {
		score -= r.Ping.JitterMS / 5
		score -= r.Ping.LossPercent() * 1.5
	}
	if r.Attempts > 1 {
		score -= float64(r.Attempts-r.Successes) / float64(r.Attempts) * 20
	}

	score = math.Round(math.Max(0, math.Min(100, score)))
	switch {
	case score >= 85:
		return int(score), "A"
	case score >= 70:
		return int(score), "B"
	case score >= 50:
		return int(score), "C"
	default:
		return int(score), "D"
	}
}

func errorText(err error, opts Options) string {
	if err != nil {
		return err.Error()
	}
	if opts.MinSuccesses > 1 {
		return "not enough successful attempts"
	}
	return "no valid Telegram response"
}

func SortByLatency(results []Result) {
	sort.SliceStable(results, func(i, j int) bool {
		a, b := results[i], results[j]
		if a.Live() != b.Live() {
			return a.Live()
		}
		if !a.Live() {
			return false
		}
		return a.LatencyMS < b.LatencyMS
	})
}

type Summary struct {
	Total   int `json:"total"`
	Live    int `json:"live"`
	Dead    int `json:"dead"`
	Invalid int `json:"invalid"`
}

func Summarize(results []Result) Summary {
	s := Summary{Total: len(results)}
	for _, r := range results {
		switch r.Status {
		case StatusLive:
			s.Live++
		case StatusDead:
			s.Dead++
		default:
			s.Invalid++
		}
	}
	return s
}

func round1(v float64) float64 {
	return float64(int64(v*10+0.5)) / 10
}

const hexDigits = "0123456789abcdef"

func hexString(b []byte) string {
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, hexDigits[c>>4], hexDigits[c&0x0F])
	}
	return string(out)
}
