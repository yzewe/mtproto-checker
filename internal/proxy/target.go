package proxy

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

type Kind string

const (
	KindMTProto  Kind = "mtproto"
	KindSocks5   Kind = "socks5"
	KindWebProxy Kind = "webproxy"
	KindTCP      Kind = "tcp"
)

type SecretMode string

const (
	ModePlain   SecretMode = "plain"
	ModeSecure  SecretMode = "secure"
	ModeFakeTLS SecretMode = "fake_tls"
	ModeNone    SecretMode = "none"
)

const DefaultSNI = "www.google.com"

type Target struct {
	Raw      string `json:"raw"`
	Kind     Kind   `json:"kind"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Secret   string `json:"secret,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Title    string `json:"title,omitempty"`

	secret []byte
}

func (t *Target) Addr() string {
	return net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
}

func (t *Target) SecretBytes() []byte { return t.secret }

func (t *Target) Mode() SecretMode { return secretMode(t.secret) }

func (t *Target) SecretKey() []byte { return secretKey(t.secret) }

func (t *Target) SNI() string { return secretSNI(t.secret) }

func (t *Target) Canonical() string {
	params := []string{
		"server=" + url.QueryEscape(t.Host),
		"port=" + strconv.Itoa(t.Port),
	}

	switch t.Kind {
	case KindMTProto:
		params = append(params, "secret="+url.QueryEscape(t.Secret))
		return "tg://proxy?" + strings.Join(params, "&")
	case KindWebProxy:
		return "tg://webproxy?server=" + url.QueryEscape(t.Host) +
			"&secret=" + url.QueryEscape(t.Secret)
	case KindSocks5:
		if t.Username != "" {
			params = append(params, "user="+url.QueryEscape(t.Username))
		}
		if t.Password != "" {
			params = append(params, "pass="+url.QueryEscape(t.Password))
		}
		return "tg://socks?" + strings.Join(params, "&")
	default:
		return t.Addr()
	}
}

func (t *Target) Key() string {
	return string(t.Kind) + "|" + t.Addr() + "|" + strings.ToLower(t.Secret) + "|" + t.Username
}

func Parse(raw string) (*Target, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, errors.New("empty proxy link")
	}

	if u, ok := asURL(s); ok {
		return fromURL(s, u)
	}
	return fromHostPort(s)
}

func asURL(s string) (*url.URL, bool) {
	candidate := s
	if !strings.Contains(s, "://") {
		lower := strings.ToLower(s)
		if !strings.HasPrefix(lower, "t.me/") && !strings.HasPrefix(lower, "telegram.me/") {
			return nil, false
		}
		candidate = "https://" + s
	}
	u, err := url.Parse(candidate)
	if err != nil || u.Host == "" && u.Opaque == "" {
		return nil, false
	}
	return u, true
}

func fromURL(raw string, u *url.URL) (*Target, error) {
	q := u.Query()
	scheme := strings.ToLower(u.Scheme)

	path := strings.Trim(u.Path, "/")
	if path == "" {
		path = u.Host
	}
	path = strings.ToLower(path)

	t := &Target{
		Raw:      raw,
		Username: firstNonEmpty(q.Get("user"), q.Get("username")),
		Password: firstNonEmpty(q.Get("pass"), q.Get("password")),
		Secret:   strings.TrimSpace(q.Get("secret")),
		Title:    q.Get("title"),
	}

	host := strings.TrimSpace(firstNonEmpty(q.Get("server"), q.Get("host")))
	portText := strings.TrimSpace(q.Get("port"))

	if host == "" && u.Hostname() != "" && path != "proxy" && path != "socks" {
		host = u.Hostname()
		portText = u.Port()
		if u.User != nil {
			t.Username = u.User.Username()
			if pw, ok := u.User.Password(); ok {
				t.Password = pw
			}
		}
	}

	switch {
	case path == "socks" || strings.HasPrefix(scheme, "socks"):
		t.Kind = KindSocks5
	case path == "webproxy":
		t.Kind = KindWebProxy
	case t.Secret != "":
		t.Kind = KindMTProto
	default:
		t.Kind = KindTCP
	}

	if host == "" {
		return nil, errors.New("missing server")
	}
	// A WEB proxy is always reached over HTTPS on the standard port.
	if t.Kind == KindWebProxy && portText == "" {
		portText = "443"
	}
	port, err := parsePort(portText)
	if err != nil {
		return nil, err
	}
	t.Host, t.Port = host, port

	return finish(t)
}

func fromHostPort(s string) (*Target, error) {
	host, portText, err := net.SplitHostPort(s)
	if err != nil {
		return nil, fmt.Errorf("not a proxy link and not host:port: %q", s)
	}
	port, err := parsePort(portText)
	if err != nil {
		return nil, err
	}
	if host == "" {
		return nil, errors.New("missing server")
	}
	return finish(&Target{Raw: s, Kind: KindTCP, Host: host, Port: port})
}

func finish(t *Target) (*Target, error) {
	if t.Kind != KindMTProto && t.Kind != KindWebProxy {
		return t, nil
	}
	secret, err := DecodeSecret(t.Secret)
	if err != nil {
		return nil, err
	}
	t.secret = secret
	return t, nil
}

func parsePort(text string) (int, error) {
	if text == "" {
		return 0, errors.New("missing port")
	}
	port, err := strconv.Atoi(text)
	if err != nil {
		return 0, fmt.Errorf("invalid port: %q", text)
	}
	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("port out of range: %d", port)
	}
	return port, nil
}

func DecodeSecret(secret string) ([]byte, error) {
	s := strings.TrimSpace(secret)
	if s == "" {
		return nil, errors.New("missing MTProto secret")
	}

	raw, err := hex.DecodeString(s)
	if err != nil {
		raw, err = decodeBase64(s)
		if err != nil {
			return nil, fmt.Errorf("secret is neither hex nor base64: %q", secret)
		}
	}

	if len(raw) < 16 {
		return nil, fmt.Errorf("MTProto secret must be at least 16 bytes, got %d", len(raw))
	}
	return raw, nil
}

func decodeBase64(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	if raw, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return raw, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}

func secretMode(secret []byte) SecretMode {
	switch {
	case len(secret) == 0:
		return ModeNone
	case len(secret) >= 17 && secret[0] == 0xEE:
		return ModeFakeTLS
	case len(secret) >= 17 && secret[0] == 0xDD:
		return ModeSecure
	default:
		return ModePlain
	}
}

func secretKey(secret []byte) []byte {
	switch {
	case len(secret) >= 17 && (secret[0] == 0xDD || secret[0] == 0xEE):
		return secret[1:17]
	case len(secret) >= 16:
		return secret[:16]
	default:
		return nil
	}
}

func secretSNI(secret []byte) string {
	if len(secret) <= 17 {
		return DefaultSNI
	}

	tail := secret[17:]
	end := len(tail)
	for i, c := range tail {
		if !isHostByte(c) {
			end = i
			break
		}
	}

	name := strings.ToLower(strings.Trim(string(tail[:end]), ".-"))
	if !strings.Contains(name, ".") || len(name) < 4 {
		return DefaultSNI
	}
	return name
}

func isHostByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	default:
		return c == '.' || c == '-'
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
