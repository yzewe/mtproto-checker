package mtproto

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/yzewe/mtproto-checker/internal/proxy"
)

type MaskingResult struct {
	Domain    string   `json:"domain"`
	Answered  bool     `json:"answered"`
	Version   string   `json:"tls_version,omitempty"`
	Issuer    string   `json:"issuer,omitempty"`
	Subject   string   `json:"subject,omitempty"`
	NameMatch bool     `json:"name_match"`
	Verdict   string   `json:"verdict"`
	Error     string   `json:"error,omitempty"`
	SANs      []string `json:"-"`
}

type ConnLimit struct {
	Requested int `json:"requested"`
	Accepted  int `json:"accepted"`
}

type StabilityStats struct {
	Seconds  float64 `json:"seconds"`
	Pings    int     `json:"pings"`
	Lost     int     `json:"lost"`
	DriftMS  float64 `json:"drift_ms"`
	Survived bool    `json:"survived"`
}

type Audit struct {
	Masking          *MaskingResult `json:"masking,omitempty"`
	AcceptsAnySecret *bool          `json:"accepts_any_secret,omitempty"`
	ConnLimit        *ConnLimit     `json:"conn_limit,omitempty"`
}

// CheckMasking speaks real TLS to a FakeTLS proxy using the domain from its
// secret. A well configured proxy forwards unrecognised clients to that site
// and answers with its certificate; a silent or broken answer is what makes a
// proxy easy to fingerprint.
func (c *Checker) CheckMasking(ctx context.Context, t *proxy.Target) *MaskingResult {
	domain := t.SNI()
	result := &MaskingResult{Domain: domain}

	if t.Mode() != proxy.ModeFakeTLS {
		result.Verdict = "not applicable"
		return result
	}

	conn, _, err := c.dial(ctx, t.Addr())
	if err != nil {
		result.Error = err.Error()
		result.Verdict = "unreachable"
		return result
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(c.Timeout))
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         domain,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		result.Error = err.Error()
		result.Verdict = "no cover traffic"
		return result
	}

	state := tlsConn.ConnectionState()
	result.Answered = true
	result.Version = tlsVersionName(state.Version)
	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		result.Subject = leaf.Subject.CommonName
		result.Issuer = leaf.Issuer.CommonName
		result.SANs = leaf.DNSNames
		result.NameMatch = leaf.VerifyHostname(domain) == nil
	}

	switch {
	case result.NameMatch:
		result.Verdict = "good"
	case result.Subject != "":
		result.Verdict = "certificate for another domain"
	default:
		result.Verdict = "answered without a certificate"
	}
	return result
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "1.3"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS10:
		return "1.0"
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}

// CheckOpenSecret repeats the handshake with a random secret. A proxy that
// still lets us through is not checking secrets at all.
func (c *Checker) CheckOpenSecret(ctx context.Context, t *proxy.Target) (bool, error) {
	if t.Kind != proxy.KindMTProto {
		return false, errors.New("only MTProto proxies have a secret")
	}

	decoy, err := decoyTarget(t)
	if err != nil {
		return false, err
	}

	quick := *c
	quick.Depth = DepthQuick
	quick.MaxCandidates = 2
	if _, err := quick.probeMTProto(ctx, decoy); err != nil {
		return false, nil
	}
	return true, nil
}

// decoyTarget copies a target, keeping the secret shape but replacing the key
// so the proxy has nothing valid to match.
func decoyTarget(t *proxy.Target) (*proxy.Target, error) {
	key, err := randomBytes(16)
	if err != nil {
		return nil, err
	}

	secret := hexString(key)
	switch t.Mode() {
	case proxy.ModeFakeTLS:
		secret = "ee" + secret + hexString([]byte(t.SNI()))
	case proxy.ModeSecure:
		secret = "dd" + secret
	}

	link := fmt.Sprintf("tg://proxy?server=%s&port=%d&secret=%s", t.Host, t.Port, secret)
	return proxy.Parse(link)
}

const hexDigits = "0123456789abcdef"

func hexString(b []byte) string {
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, hexDigits[c>>4], hexDigits[c&0x0F])
	}
	return string(out)
}

// CheckConnLimit opens several handshakes at once to find out how many
// simultaneous clients the proxy is willing to serve.
func (c *Checker) CheckConnLimit(ctx context.Context, t *proxy.Target, want int) *ConnLimit {
	if want < 2 {
		want = 2
	}

	quick := *c
	quick.Depth = DepthQuick
	quick.MaxCandidates = 1

	var wg sync.WaitGroup
	results := make([]bool, want)
	for i := range want {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := quick.Probe(ctx, t)
			results[i] = err == nil
		}()
	}
	wg.Wait()

	accepted := 0
	for _, ok := range results {
		if ok {
			accepted++
		}
	}
	return &ConnLimit{Requested: want, Accepted: accepted}
}

// hold keeps the session alive for the given time, pinging periodically, to
// catch proxies that drop or degrade after the first seconds.
func (s *session) hold(str *stream, total, interval, perPing time.Duration) *StabilityStats {
	if interval <= 0 {
		interval = 5 * time.Second
	}

	stats := &StabilityStats{Seconds: round3(total.Seconds()), Survived: true}
	deadline := time.Now().Add(total)

	var first, last time.Duration
	for time.Now().Before(deadline) {
		sleep := interval
		if remaining := time.Until(deadline); remaining < sleep {
			sleep = remaining
		}
		time.Sleep(sleep)

		if perPing > 0 {
			str.setDeadline(time.Now().Add(perPing))
		}
		stats.Pings++

		rtt, err := s.ping(str)
		if err != nil {
			stats.Lost++
			stats.Survived = false
			break
		}
		if first == 0 {
			first = rtt
		}
		last = rtt
	}

	if first > 0 && last > 0 {
		stats.DriftMS = round1(ms(last) - ms(first))
	}
	return stats
}

func describeAudit(a *Audit) string {
	if a == nil {
		return ""
	}
	var parts []string
	if a.Masking != nil && a.Masking.Verdict != "not applicable" {
		parts = append(parts, "masking "+a.Masking.Verdict)
	}
	if a.AcceptsAnySecret != nil && *a.AcceptsAnySecret {
		parts = append(parts, "accepts any secret")
	}
	if a.ConnLimit != nil {
		parts = append(parts, fmt.Sprintf("parallel %d/%d", a.ConnLimit.Accepted, a.ConnLimit.Requested))
	}
	return strings.Join(parts, ", ")
}
