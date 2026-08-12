package filter

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/yzewe/mtproto-checker/internal/checker"
	"github.com/yzewe/mtproto-checker/internal/proxy"
)

type Spec struct {
	Modes     []string
	Ports     []int
	Countries []string
	ASNs      []int
	Exclude   map[string]bool
}

func (s Spec) NeedsGeo() bool { return len(s.Countries) > 0 || len(s.ASNs) > 0 }

func ParseList(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.ToLower(strings.TrimSpace(part)); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func ParseInts(value string) ([]int, error) {
	var out []int
	for _, part := range ParseList(value) {
		part = strings.TrimPrefix(part, "as")
		number, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("not a number: %q", part)
		}
		out = append(out, number)
	}
	return out, nil
}

func (s Spec) Links(links []string) []string {
	if len(s.Modes) == 0 && len(s.Ports) == 0 && len(s.Exclude) == 0 {
		return links
	}

	out := make([]string, 0, len(links))
	for _, link := range links {
		target, err := proxy.Parse(link)
		if err != nil {

			out = append(out, link)
			continue
		}
		if s.Exclude[target.Key()] || s.Exclude[strings.ToLower(target.Host)] {
			continue
		}
		if len(s.Ports) > 0 && !containsInt(s.Ports, target.Port) {
			continue
		}
		if len(s.Modes) > 0 && !containsString(s.Modes, modeOf(target)) {
			continue
		}
		out = append(out, link)
	}
	return out
}

func (s Spec) Results(results []checker.Result) []checker.Result {
	if !s.NeedsGeo() {
		return results
	}

	out := make([]checker.Result, 0, len(results))
	for _, r := range results {
		if len(s.Countries) > 0 {
			if r.Geo == nil || !containsString(s.Countries, strings.ToLower(r.Geo.Code)) {
				continue
			}
		}
		if len(s.ASNs) > 0 {
			if r.Geo == nil || !containsInt(s.ASNs, r.Geo.ASN) {
				continue
			}
		}
		out = append(out, r)
	}
	return out
}

func LoadExclusions(lines []string) map[string]bool {
	exclude := map[string]bool{}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if target, err := proxy.Parse(line); err == nil {
			exclude[target.Key()] = true
			exclude[strings.ToLower(target.Host)] = true
			continue
		}
		exclude[strings.ToLower(line)] = true
	}
	return exclude
}

func modeOf(t *proxy.Target) string {
	if t.Kind == proxy.KindMTProto {
		return string(t.Mode())
	}
	return string(t.Kind)
}

func containsString(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

func containsInt(list []int, want int) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}
