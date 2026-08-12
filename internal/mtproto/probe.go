package mtproto

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/yzewe/mtproto-checker/internal/proxy"
)

type Depth string

const (
	DepthQuick Depth = "quick"

	DepthFull Depth = "full"
)

type Route struct {
	Protocol  string `json:"protocol"`
	DC        int    `json:"dc,omitempty"`
	Transport string `json:"transport,omitempty"`
	Via       string `json:"via,omitempty"`
	Depth     Depth  `json:"depth,omitempty"`

	ServerTimeSkew int64 `json:"server_time_skew,omitempty"`
}

func (r Route) String() string {
	suffix := ""
	if r.Depth == DepthFull {
		suffix = " +authkey"
	}
	return r.base() + suffix
}

func (r Route) base() string {
	switch {
	case r.Via != "":
		return fmt.Sprintf("%s -> %s", r.Protocol, r.Via)
	case r.DC != 0:
		return fmt.Sprintf("%s dc%d/%s", r.Protocol, r.DC, r.Transport)
	default:
		return r.Protocol
	}
}

type Timings struct {
	ConnectMS   float64 `json:"connect_ms,omitempty"`
	HandshakeMS float64 `json:"handshake_ms,omitempty"`
	RespQMS     float64 `json:"respq_ms,omitempty"`

	TotalMS float64 `json:"total_ms,omitempty"`
}

type PingStats struct {
	Sent     int     `json:"sent"`
	Received int     `json:"received"`
	MedianMS float64 `json:"median_ms,omitempty"`
	MinMS    float64 `json:"min_ms,omitempty"`
	MaxMS    float64 `json:"max_ms,omitempty"`
	JitterMS float64 `json:"jitter_ms,omitempty"`
}

func (p *PingStats) LossPercent() float64 {
	if p == nil || p.Sent == 0 {
		return 0
	}
	return float64(p.Sent-p.Received) / float64(p.Sent) * 100
}

type Outcome struct {
	Route     Route           `json:"route"`
	Timings   Timings         `json:"timings"`
	Ping      *PingStats      `json:"ping,omitempty"`
	Nearest   *NearestDC      `json:"nearest_dc,omitempty"`
	Config    *ConfigInfo     `json:"config,omitempty"`
	Speed     *SpeedStats     `json:"speed,omitempty"`
	Stability *StabilityStats `json:"stability,omitempty"`
}

type Stage int

const (
	StageDial Stage = iota
	StageHandshake
	StageProtocol
)

type Kind string

const (
	KindDialTimeout    Kind = "dial_timeout"
	KindDialRefused    Kind = "dial_refused"
	KindDNS            Kind = "dns_failed"
	KindUnreachable    Kind = "unreachable"
	KindSecretRejected Kind = "secret_rejected"
	KindHandshake      Kind = "handshake_failed"
	KindTimeout        Kind = "timeout"
	KindClosed         Kind = "connection_closed"
	KindNoResPQ        Kind = "no_respq"
	KindSocksAuth      Kind = "socks_auth_failed"
	KindSocksRejected  Kind = "socks_rejected"
	KindCanceled       Kind = "canceled"
	KindOther          Kind = "other"
)

type Error struct {
	Stage Stage
	Kind  Kind
	Err   error
}

func (e *Error) Error() string { return e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

func fail(stage Stage, err error) *Error {
	return &Error{Stage: stage, Kind: classify(stage, err), Err: err}
}

func failAs(stage Stage, kind Kind, err error) *Error {
	return &Error{Stage: stage, Kind: kind, Err: err}
}

func classify(stage Stage, err error) Kind {
	if err == nil {
		return KindOther
	}
	if errors.Is(err, context.Canceled) {
		return KindCanceled
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return KindDNS
	}

	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
		if stage == StageDial {
			return KindDialTimeout
		}
		return KindTimeout
	}

	text := err.Error()
	switch {
	case strings.Contains(text, "connection refused"):
		return KindDialRefused
	case strings.Contains(text, "no route to host"), strings.Contains(text, "network is unreachable"):
		return KindUnreachable
	case strings.Contains(text, "HMAC mismatch"):
		return KindSecretRejected
	case strings.Contains(text, "EOF"), strings.Contains(text, "connection reset"):
		return KindClosed
	}

	switch stage {
	case StageDial:
		return KindUnreachable
	case StageHandshake:
		return KindHandshake
	default:
		return KindNoResPQ
	}
}

func KindOf(err error) Kind {
	var probeErr *Error
	if errors.As(err, &probeErr) {
		return probeErr.Kind
	}
	if err == nil {
		return ""
	}
	return classify(StageProtocol, err)
}

var telegramDCs = []struct {
	ID   int
	Addr string
}{
	{2, "149.154.167.51:443"},
	{1, "149.154.175.53:443"},
	{4, "149.154.167.91:443"},
	{3, "149.154.175.100:443"},
	{5, "91.108.56.130:443"},
}

var dcOrder = []int{2, 1, 4, 3, 5}

const DefaultPings = 3

type Checker struct {
	Timeout time.Duration
	Dialer  *net.Dialer

	MaxCandidates int

	Depth Depth

	Pings int

	APIID int

	Inspect bool

	Speedtest bool

	Hold time.Duration
}

func New(timeout time.Duration) *Checker {
	return &Checker{
		Timeout:       timeout,
		Dialer:        &net.Dialer{Timeout: timeout},
		MaxCandidates: 6,
		Depth:         DepthQuick,
		Pings:         DefaultPings,
	}
}

func (c *Checker) Probe(ctx context.Context, t *proxy.Target) (Outcome, error) {
	switch t.Kind {
	case proxy.KindSocks5:
		return c.probeSocks5(ctx, t)
	case proxy.KindMTProto:
		return c.probeMTProto(ctx, t)
	default:
		return c.probeTCP(ctx, t)
	}
}

func (c *Checker) dial(ctx context.Context, addr string) (net.Conn, time.Duration, error) {
	started := time.Now()
	conn, err := c.Dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, 0, fail(StageDial, err)
	}
	elapsed := time.Since(started)

	if err := conn.SetDeadline(time.Now().Add(c.budget())); err != nil {
		conn.Close()
		return nil, elapsed, fail(StageDial, err)
	}
	return conn, elapsed, nil
}

func (c *Checker) probeTCP(ctx context.Context, t *proxy.Target) (Outcome, error) {
	conn, connectTime, err := c.dial(ctx, t.Addr())
	if err != nil {
		return Outcome{}, err
	}
	defer conn.Close()

	if _, err := conn.Write([]byte{0, 0, 0, 0, 0, 0, 0, 0}); err != nil {
		return Outcome{}, fail(StageHandshake, err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err != nil {
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			return Outcome{}, failAs(StageHandshake, KindClosed,
				fmt.Errorf("connection closed after TCP probe: %w", err))
		}
	}
	return Outcome{
		Route:   Route{Protocol: "tcp"},
		Timings: Timings{ConnectMS: ms(connectTime)},
	}, nil
}

// candidateWindow bounds the retries across datacenters and transports. A
// failing candidate gives up after one round trip, so this does not need to
// cover the optional stages.
func (c *Checker) candidateWindow() time.Duration {
	if c.depth() == DepthFull {
		return 3 * c.Timeout
	}
	return 2 * c.Timeout
}

type candidate struct {
	dc int
	tr transport
}

func (c *Checker) probeMTProto(ctx context.Context, t *proxy.Target) (Outcome, error) {
	fakeTLS := t.Mode() == proxy.ModeFakeTLS

	order := []transport{intermediate, abridged, paddedIntermediate}
	if fakeTLS || t.Mode() == proxy.ModeSecure {
		order = []transport{paddedIntermediate, intermediate, abridged}
	}

	var candidates []candidate
	for _, dc := range dcOrder {
		for _, tr := range order {
			candidates = append(candidates, candidate{dc: dc, tr: tr})
		}
	}
	if c.MaxCandidates > 0 && len(candidates) > c.MaxCandidates {
		candidates = candidates[:c.MaxCandidates]
	}

	deadline := time.Now().Add(c.candidateWindow())
	var problems []string
	var lastErr error
	for i, cand := range candidates {
		if i > 0 && time.Now().After(deadline) {
			problems = append(problems, "candidate budget exhausted")
			break
		}
		outcome, err := c.attemptMTProto(ctx, t, cand, fakeTLS)
		if err == nil {
			return outcome, nil
		}
		lastErr = err

		var probeErr *Error
		if errors.As(err, &probeErr) && probeErr.Stage != StageProtocol {

			return Outcome{}, err
		}
		problems = append(problems, fmt.Sprintf("dc%d/%s: %v", cand.dc, cand.tr.name, err))
		if ctx.Err() != nil {
			return Outcome{}, fail(StageDial, ctx.Err())
		}
	}
	return Outcome{}, failAs(StageProtocol, KindOf(lastErr), errors.New(summarize(problems, 3)))
}

func (c *Checker) attemptMTProto(ctx context.Context, t *proxy.Target, cand candidate, fakeTLS bool) (Outcome, error) {
	conn, connectTime, err := c.dial(ctx, t.Addr())
	if err != nil {
		return Outcome{}, err
	}
	defer conn.Close()

	timings := Timings{ConnectMS: ms(connectTime)}
	protocol := "mtproto"
	var carrier io.ReadWriter = conn

	if fakeTLS {
		started := time.Now()
		if err := c.fakeTLSHandshake(conn, t); err != nil {
			return Outcome{}, err
		}
		timings.HandshakeMS = ms(time.Since(started))
		carrier = newTLSConn(conn)
		protocol = "faketls"
	}

	outcome := Outcome{
		Route: Route{Protocol: protocol, DC: cand.dc, Transport: cand.tr.name, Depth: c.depth()},
	}
	stages, err := c.handshake(conn, carrier, t.SecretKey(), cand)
	if err != nil {
		return Outcome{}, err
	}

	timings.RespQMS = ms(stages.respq)
	outcome.Route.ServerTimeSkew = stages.skew
	outcome.Timings = timings
	outcome.Ping = stages.ping
	outcome.Nearest = stages.nearest
	outcome.Config = stages.config
	outcome.Speed = stages.speed
	outcome.Stability = stages.stability
	return outcome, nil
}

type stageResults struct {
	skew      int64
	respq     time.Duration
	ping      *PingStats
	nearest   *NearestDC
	config    *ConfigInfo
	speed     *SpeedStats
	stability *StabilityStats
}

// TotalBudget bounds one attempt, including the retries across candidates.
// TotalBudget bounds one attempt end to end.
func (c *Checker) TotalBudget() time.Duration {
	return c.candidateWindow() + c.budget() + c.Timeout
}

func (c *Checker) budget() time.Duration {
	if c.depth() != DepthFull {
		return c.Timeout
	}

	budget := 4 * c.Timeout
	if c.Inspect {
		budget += 2 * c.Timeout
	}
	if c.Speedtest {
		budget += 2 * c.Timeout
	}
	return budget + c.Hold
}

func (c *Checker) depth() Depth {
	if c.Depth == DepthFull {
		return DepthFull
	}
	return DepthQuick
}

func (c *Checker) pings() int {
	if c.Pings <= 0 {
		return DefaultPings
	}
	return c.Pings
}

func (c *Checker) fakeTLSHandshake(conn net.Conn, t *proxy.Target) error {
	hello, err := buildClientHello(t.SNI(), t.SecretKey())
	if err != nil {
		return fail(StageHandshake, err)
	}
	if _, err := conn.Write(hello.bytes); err != nil {
		return fail(StageHandshake, err)
	}
	response, err := readServerHello(conn)
	if err != nil {
		return fail(StageHandshake, fmt.Errorf("no FakeTLS ServerHello: %w", err))
	}
	if err := verifyServerHello(response, t.SecretKey(), hello.sessionID, hello.random); err != nil {
		return failAs(StageHandshake, KindSecretRejected, err)
	}
	return nil
}

func (c *Checker) handshake(conn net.Conn, carrier io.ReadWriter, secretKey []byte, cand candidate) (stageResults, error) {
	var out stageResults

	obf, err := newObfConn(carrier, secretKey, cand.tr.tag, cand.dc)
	if err != nil {
		return out, fail(StageProtocol, err)
	}

	s := &stream{w: obf, r: obf, tr: cand.tr, deadline: deadlineSetter(conn), perStep: c.Timeout}
	if c.depth() == DepthQuick {
		if err := quickCheck(s); err != nil {
			return out, fail(StageProtocol, err)
		}
		out.respq = s.firstRoundTrip()
		return out, nil
	}
	return c.fullHandshake(s, cand.dc)
}

func (c *Checker) fullHandshake(s *stream, dcID int) (stageResults, error) {
	var out stageResults

	auth, err := createAuthKey(s, dcID)
	if err != nil {
		return out, fail(StageProtocol, err)
	}
	out.skew = auth.timeOffset
	out.respq = s.firstRoundTrip()

	sess, err := newSession(auth)
	if err != nil {
		return out, fail(StageProtocol, err)
	}

	out.ping, err = sess.pingSeries(s, c.pings(), c.Timeout)
	if err != nil {
		return out, fail(StageProtocol, err)
	}

	// Everything below is optional: a failure here says something about the
	// proxy, not about whether it works, so it must not turn a live proxy dead.
	if c.Inspect && c.APIID != 0 {
		if nearest, err := getNearestDC(sess, s, c.APIID, c.Timeout); err == nil {
			out.nearest = nearest
		} else {
			return out, fail(StageProtocol, fmt.Errorf("help.getNearestDc: %w", err))
		}
		if config, err := getConfig(sess, s, c.APIID, c.Timeout); err == nil {
			out.config = config
		}
	}

	if c.Speedtest && c.APIID != 0 {
		if speed, err := measureDownload(sess, s, c.APIID, 2*c.Timeout); err == nil {
			out.speed = speed
		}
	}

	if c.Hold > 0 {
		out.stability = sess.hold(s, c.Hold, 5*time.Second, c.Timeout)
	}
	return out, nil
}

func deadlineSetter(conn net.Conn) func(time.Time) {
	if conn == nil {
		return nil
	}
	return func(t time.Time) { _ = conn.SetDeadline(t) }
}

func summarize(problems []string, keep int) string {
	if len(problems) == 0 {
		return "no valid resPQ from Telegram"
	}
	if len(problems) > keep {
		problems = problems[:keep]
	}
	return strings.Join(problems, "; ")
}

func ms(d time.Duration) float64 {
	return float64(d.Microseconds()) / 1000
}

func summarizeDurations(samples []time.Duration, sent int) *PingStats {
	stats := &PingStats{Sent: sent, Received: len(samples)}
	if len(samples) == 0 {
		return stats
	}

	if len(samples) > 1 {
		var total time.Duration
		for i := 1; i < len(samples); i++ {
			delta := samples[i] - samples[i-1]
			if delta < 0 {
				delta = -delta
			}
			total += delta
		}
		stats.JitterMS = ms(total / time.Duration(len(samples)-1))
	}

	sorted := append([]time.Duration{}, samples...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	stats.MinMS = ms(sorted[0])
	stats.MaxMS = ms(sorted[len(sorted)-1])
	stats.MedianMS = ms(sorted[len(sorted)/2])
	return stats
}
