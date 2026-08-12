package geo

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

type Info struct {
	Host    string  `json:"host"`
	IP      string  `json:"ip,omitempty"`
	Country string  `json:"country,omitempty"`
	Code    string  `json:"country_code,omitempty"`
	City    string  `json:"city,omitempty"`
	ASN     int     `json:"asn,omitempty"`
	Org     string  `json:"org,omitempty"`
	ISP     string  `json:"isp,omitempty"`
	Lat     float64 `json:"latitude,omitempty"`
	Lon     float64 `json:"longitude,omitempty"`
	Error   string  `json:"error,omitempty"`
}

func (i *Info) Flag() string {
	if i == nil || len(i.Code) != 2 {
		return ""
	}
	runes := []rune{}
	for _, c := range i.Code {
		if c < 'A' || c > 'Z' {
			return ""
		}
		runes = append(runes, 0x1F1E6+(c-'A'))
	}
	return string(runes)
}

func (i *Info) Short() string {
	if i == nil {
		return ""
	}
	if i.Error != "" {
		return i.Error
	}
	out := i.Code
	if i.City != "" {
		out += ", " + i.City
	}
	if i.ASN != 0 {
		out += fmt.Sprintf(" AS%d", i.ASN)
	}
	if org := firstNonEmpty(i.Org, i.ISP); org != "" {
		out += " " + org
	}
	return out
}

type Client struct {
	HTTP     *http.Client
	Resolver *net.Resolver

	mu    sync.Mutex
	cache map[string]*Info
}

func NewClient(timeout time.Duration) *Client {
	return &Client{
		HTTP:  &http.Client{Timeout: timeout},
		cache: map[string]*Info{},
	}
}

func (c *Client) Lookup(ctx context.Context, host string) *Info {
	c.mu.Lock()
	if info, ok := c.cache[host]; ok {
		c.mu.Unlock()
		return info
	}
	c.mu.Unlock()

	info := c.lookup(ctx, host)

	c.mu.Lock()
	c.cache[host] = info
	c.mu.Unlock()
	return info
}

func (c *Client) lookup(ctx context.Context, host string) *Info {
	info := &Info{Host: host}

	ip := net.ParseIP(host)
	if ip == nil {
		resolver := c.Resolver
		if resolver == nil {
			resolver = net.DefaultResolver
		}
		addrs, err := resolver.LookupIPAddr(ctx, host)
		if err != nil || len(addrs) == 0 {
			info.Error = fmt.Sprintf("cannot resolve %s", host)
			return info
		}
		ip = addrs[0].IP
	}
	info.IP = ip.String()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://ipwho.is/"+info.IP, nil)
	if err != nil {
		info.Error = err.Error()
		return info
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		info.Error = "ipwho.is: " + err.Error()
		return info
	}
	defer resp.Body.Close()

	var payload struct {
		Success    *bool   `json:"success"`
		Message    string  `json:"message"`
		Country    string  `json:"country"`
		Code       string  `json:"country_code"`
		City       string  `json:"city"`
		Latitude   float64 `json:"latitude"`
		Longitude  float64 `json:"longitude"`
		Connection struct {
			ASN int    `json:"asn"`
			Org string `json:"org"`
			ISP string `json:"isp"`
		} `json:"connection"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		info.Error = "ipwho.is: malformed response"
		return info
	}
	if payload.Success != nil && !*payload.Success {
		info.Error = "ipwho.is: " + firstNonEmpty(payload.Message, "lookup failed")
		return info
	}

	info.Country = payload.Country
	info.Code = payload.Code
	info.City = payload.City
	info.Lat = payload.Latitude
	info.Lon = payload.Longitude
	info.ASN = payload.Connection.ASN
	info.Org = payload.Connection.Org
	info.ISP = payload.Connection.ISP
	return info
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
