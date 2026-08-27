// Package webproxy speaks the Telegram WEB proxy protocol (tproxy-server): an
// MTProxy stream carried as multiplexed frames over HTTPS or WebSocket.
//
// See https://github.com/telegramdesktop/tproxy-server, PROTOCOL.md.
package webproxy

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// bridgeLabel is the frozen v1 domain-separation label from the protocol.
const bridgeLabel = "tdesktop-web-proxy-bridge-v1\n"

const (
	streamID       = 1
	windowGrantMin = 256 << 10
	maxBodyBytes   = 8 << 20
)

// bootstrapPattern matches the short-lived token embedded in the bridge page.
var bootstrapPattern = regexp.MustCompile(`bootstrap="([A-Za-z0-9_-]{43})"`)

// carrierPattern matches the carrier mode the profile selected.
var carrierPattern = regexp.MustCompile(`carrierMode="([a-z-]+)"`)

// Stage names the step a dial failed at, so a caller can tell a wrong secret
// from an unreachable host.
type Stage string

const (
	StageBridge  Stage = "bridge"
	StageSession Stage = "session"
	StageStream  Stage = "stream"
)

// Error is a dial failure annotated with the stage it happened at.
type Error struct {
	Stage Stage
	Err   error
}

func (e *Error) Error() string { return e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

func failure(stage Stage, format string, args ...any) *Error {
	return &Error{Stage: stage, Err: fmt.Errorf(format, args...)}
}

// Capability derives the bridge capability from the host and MTProxy secret.
func Capability(host string, secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(bridgeLabel + strings.ToLower(host)))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// Carrier is one relay session carrying a single MTProxy stream. It behaves
// like a connection, so the MTProto code can run over it unchanged.
type Carrier struct {
	client   *http.Client
	origin   string
	host     string
	session  string
	mode     string
	lanes    bool
	timeout  time.Duration
	deadline time.Time

	transport carrierTransport

	opened     bool
	closed     bool
	readBuf    []byte
	eof        bool
	windowDebt uint32
}

// carrierTransport is the part that differs between the HTTPS and WebSocket
// carrier modes: sending a batch of frames and collecting the next one.
type carrierTransport interface {
	send(ctx context.Context, frames []byte) error
	receive(ctx context.Context) ([]byte, error)
	close()
}

// Options configure a dial.
type Options struct {
	Host    string
	Secret  []byte
	Timeout time.Duration
	// Insecure skips certificate verification, for hosts that front the bridge
	// with a self-signed certificate.
	Insecure bool
}

// Dial fetches the bridge page, creates a relay session and opens one stream.
func Dial(ctx context.Context, opts Options) (*Carrier, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	host := strings.ToLower(strings.TrimSpace(opts.Host))
	if host == "" {
		return nil, failure(StageBridge, "missing host")
	}

	c := &Carrier{
		client:  newHTTPClient(opts),
		origin:  "https://" + host,
		host:    host,
		timeout: opts.Timeout,
	}

	bootstrap, mode, err := c.fetchBridge(ctx, Capability(host, opts.Secret))
	if err != nil {
		return nil, err
	}
	c.mode = mode

	if err := c.createSession(ctx, bootstrap); err != nil {
		return nil, err
	}

	switch c.mode {
	case "https", "https-lanes":
		c.lanes = c.mode == "https-lanes"
		c.transport = newHTTPCarrier(c)
	case "websocket", "websocket-lanes":
		socket, err := dialWebSocket(ctx, c)
		if err != nil {
			return nil, err
		}
		c.lanes = c.mode == "websocket-lanes"
		c.transport = socket
	default:
		return nil, failure(StageSession, "unsupported carrier mode %q", c.mode)
	}
	return c, nil
}

// Mode reports the carrier mode the proxy selected.
func (c *Carrier) Mode() string { return c.mode }

func newHTTPClient(opts Options) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DisableCompression = true
	transport.ResponseHeaderTimeout = 0
	if opts.Insecure {
		transport.TLSClientConfig = insecureTLS()
	}
	return &http.Client{
		Transport: transport,
		// Redirects would leave the authenticated origin.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (c *Carrier) fetchBridge(ctx context.Context, capability string) (bootstrap, mode string, err error) {
	url := c.origin + "/?bridge=" + capability

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", "", failure(StageBridge, "%w", err)
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := c.client.Do(req)
	if err != nil {
		return "", "", failure(StageBridge, "%w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return "", "", failure(StageBridge, "reading the bridge page: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", "", failure(StageBridge, "bridge answered %s", resp.Status)
	}

	match := bootstrapPattern.FindSubmatch(body)
	if match == nil {
		// The public index is what a wrong capability gets.
		return "", "", failure(StageBridge, "no bootstrap token in the page: the secret does not match this host")
	}
	mode = "https"
	if found := carrierPattern.FindSubmatch(body); found != nil {
		mode = string(found[1])
	}
	return string(match[1]), mode, nil
}

func (c *Carrier) createSession(ctx context.Context, bootstrap string) error {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	hello := encodeFrame(frameHello, 0, []byte{1})
	req, err := c.newAPIRequest(ctx, http.MethodPost, "/api/v1/session", bootstrap, hello)
	if err != nil {
		return failure(StageSession, "%w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return failure(StageSession, "%w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return failure(StageSession, "reading the session answer: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return failure(StageSession, "session creation answered %s", resp.Status)
	}

	session := resp.Header.Get("X-Session-Token")
	if session == "" {
		return failure(StageSession, "no X-Session-Token in the answer")
	}
	c.session = session
	if mode := resp.Header.Get("X-Carrier-Mode"); mode != "" {
		c.mode = mode
	}

	frames, err := decodeFrames(body)
	if err != nil {
		return failure(StageSession, "malformed session answer: %w", err)
	}
	if len(frames) != 1 || frames[0].kind != frameWelcome {
		return failure(StageSession, "expected WELCOME, got %s", describeFrames(frames))
	}
	return nil
}

func (c *Carrier) newAPIRequest(ctx context.Context, method, path, bearer string, body []byte) (*http.Request, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.origin+path, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Origin", c.origin)
	req.Header.Set("User-Agent", userAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/octet-stream")
		req.ContentLength = int64(len(body))
	}
	return req, nil
}

// Write sends bytes as DATA frames for our stream, opening it on first use.
func (c *Carrier) Write(p []byte) (int, error) {
	if c.closed {
		return 0, net.ErrClosed
	}

	var batch []byte
	if !c.opened {
		batch = append(batch, encodeFrame(frameOpen, streamID, nil)...)
		c.opened = true
	}
	batch = append(batch, c.takeWindowGrant(0)...)

	for offset := 0; offset < len(p); offset += chunkSize {
		end := min(offset+chunkSize, len(p))
		batch = append(batch, encodeFrame(frameData, streamID, p[offset:end])...)
	}

	ctx, cancel := c.requestContext()
	defer cancel()
	if err := c.transport.send(ctx, batch); err != nil {
		return 0, err
	}
	return len(p), nil
}

const chunkSize = 64 << 10

// Read returns bytes the relay sent for our stream, polling until some arrive.
func (c *Carrier) Read(p []byte) (int, error) {
	for len(c.readBuf) == 0 {
		if c.eof {
			return 0, io.EOF
		}
		if c.closed {
			return 0, net.ErrClosed
		}
		if err := c.pump(); err != nil {
			return 0, err
		}
	}

	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	c.windowDebt += uint32(n)
	if c.windowDebt >= windowGrantMin {
		c.grantWindow()
	}
	return n, nil
}

// pump performs one carrier exchange and files away whatever came back.
func (c *Carrier) pump() error {
	ctx, cancel := c.requestContext()
	defer cancel()

	body, err := c.transport.receive(ctx)
	if err != nil {
		return err
	}
	if len(body) == 0 {
		return nil
	}

	frames, err := decodeFrames(body)
	if err != nil {
		return err
	}
	for _, f := range frames {
		switch f.kind {
		case frameData:
			if f.stream == streamID {
				c.readBuf = append(c.readBuf, f.payload...)
			}
		case frameClose:
			if f.stream == streamID {
				c.eof = true
			}
		case framePing:
			c.sendControl(encodeFrame(framePong, 0, f.payload))
		case frameBye:
			c.eof = true
			return fmt.Errorf("relay closed the session: %s", trimReason(f.payload))
		}
	}
	return nil
}

// grantWindow returns consumed credit so the relay keeps sending.
func (c *Carrier) grantWindow() {
	if grant := c.takeWindowGrant(0); len(grant) > 0 {
		c.sendControl(grant)
	}
}

func (c *Carrier) takeWindowGrant(minimum uint32) []byte {
	if c.windowDebt <= minimum {
		return nil
	}
	delta := make([]byte, 4)
	delta[0] = byte(c.windowDebt >> 24)
	delta[1] = byte(c.windowDebt >> 16)
	delta[2] = byte(c.windowDebt >> 8)
	delta[3] = byte(c.windowDebt)
	c.windowDebt = 0
	return encodeFrame(frameWindow, streamID, delta)
}

// sendControl pushes frames that carry no payload of our own; failures here are
// not worth aborting a check for.
func (c *Carrier) sendControl(batch []byte) {
	if len(batch) == 0 || c.closed {
		return
	}
	ctx, cancel := c.requestContext()
	defer cancel()
	_ = c.transport.send(ctx, batch)
}

// Close tears down the stream and the relay session.
func (c *Carrier) Close() error {
	if c.closed {
		return nil
	}
	if c.opened {
		c.sendControl(encodeFrame(frameClose, streamID, nil))
	}
	c.closed = true
	c.transport.close()
	c.deleteSession()
	return nil
}

// deleteSession releases the relay session instead of leaving it to expire.
func (c *Carrier) deleteSession() {
	if c.session == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	req, err := c.newAPIRequest(ctx, http.MethodDelete, "/api/v1/session", c.session, nil)
	if err != nil {
		return
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
}

// SetDeadline bounds the remaining carrier operations.
func (c *Carrier) SetDeadline(t time.Time) { c.deadline = t }

func (c *Carrier) requestContext() (context.Context, context.CancelFunc) {
	deadline := time.Now().Add(c.timeout)
	if !c.deadline.IsZero() && c.deadline.Before(deadline) {
		deadline = c.deadline
	}
	return context.WithDeadline(context.Background(), deadline)
}

func describeFrames(frames []frame) string {
	if len(frames) == 0 {
		return "nothing"
	}
	names := make([]string, 0, len(frames))
	for _, f := range frames {
		names = append(names, frameName(f.kind))
	}
	return strings.Join(names, ", ")
}

func trimReason(payload []byte) string {
	reason := strings.TrimSpace(string(payload))
	if reason == "" {
		return "no reason given"
	}
	if len(reason) > 120 {
		reason = reason[:120]
	}
	return strconv.Quote(reason)
}

var errUnexpectedStatus = errors.New("unexpected carrier status")

const userAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
