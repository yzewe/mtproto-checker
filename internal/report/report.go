package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/yzewe/mtproto-checker/internal/checker"
)

type Style struct {
	Color   bool
	Verbose bool
}

const (
	reset  = "\033[0m"
	green  = "\033[32m"
	red    = "\033[31m"
	yellow = "\033[33m"
	cyan   = "\033[36m"
	dim    = "\033[2m"
)

func (s Style) paint(color, text string) string {
	if !s.Color {
		return text
	}
	return color + text + reset
}

func (s Style) Text(w io.Writer, results []checker.Result) {
	for _, r := range results {
		switch r.Status {
		case checker.StatusLive:
			route := ""
			if r.Route != nil {
				route = " via " + r.Route.String()
			}
			fmt.Fprintf(w, "%s %s %s  %s%s%s\n",
				s.paint(green, "[LIVE]"),
				s.paint(gradeColor(r.Grade), grade(r)),
				hostPort(r),
				formatLatency(r.LatencyMS),
				s.paint(dim, route),
				s.paint(dim, attemptSuffix(r)),
			)
		case checker.StatusInvalid:
			fmt.Fprintf(w, "%s %s (%s)\n", s.paint(yellow, "[INVALID]"), r.Input, r.Error)
			continue
		default:
			fmt.Fprintf(w, "%s %s (%s)%s\n",
				s.paint(red, "[DEAD]"),
				hostPort(r),
				r.Error,
				s.paint(dim, attemptSuffix(r)),
			)
		}

		if !s.Verbose {
			continue
		}
		for _, line := range details(r) {
			fmt.Fprintf(w, "%s\n", s.paint(dim, "           "+line))
		}
	}
}

func details(r checker.Result) []string {
	var lines []string
	if r.Title != "" {
		lines = append(lines, "title:  "+r.Title)
	}
	if t := r.Timings; t != nil && (t.ConnectMS > 0 || t.RespQMS > 0) {
		phases := fmt.Sprintf("connect %.1f", t.ConnectMS)
		if t.HandshakeMS > 0 {
			phases += fmt.Sprintf(" · handshake %.1f", t.HandshakeMS)
		}
		if t.RespQMS > 0 {
			phases += fmt.Sprintf(" · resPQ %.1f", t.RespQMS)
		}
		lines = append(lines, "phases: "+phases+" ms")
	}
	if p := r.Ping; p != nil && p.Sent > 0 {
		line := fmt.Sprintf("ping:   %d/%d, median %.1f ms, jitter %.1f ms", p.Received, p.Sent, p.MedianMS, p.JitterMS)
		if loss := p.LossPercent(); loss > 0 {
			line += fmt.Sprintf(", loss %.0f%%", loss)
		}
		lines = append(lines, line)
	}
	if r.Secret != nil {
		line := "secret: " + string(r.Secret.Mode)
		if r.Secret.Domain != "" {
			line += ", sni=" + r.Secret.Domain
		}
		lines = append(lines, line)
	}
	if r.Geo != nil {
		lines = append(lines, "geo:    "+r.Geo.IP+" "+r.Geo.Flag()+" "+r.Geo.Short())
	}
	if n := r.Nearest; n != nil {
		line := fmt.Sprintf("exit:   %s, Telegram put us on dc%d", n.Country, n.ThisDC)
		if r.Geo != nil && r.Geo.Code != "" && !strings.EqualFold(r.Geo.Code, n.Country) {
			line += fmt.Sprintf("  (host is in %s)", r.Geo.Code)
		}
		lines = append(lines, line)
	}
	if cfg := r.Config; cfg != nil && cfg.Parsed {
		line := fmt.Sprintf("config: %d datacenters", len(cfg.Options))
		if len(cfg.Unexpected) > 0 {
			line += ", foreign addresses: " + strings.Join(cfg.Unexpected, ", ")
		} else {
			line += ", all official"
		}
		lines = append(lines, line)
	}
	if sp := r.Speed; sp != nil && sp.Bytes > 0 {
		lines = append(lines, fmt.Sprintf("speed:  %.0f KB/s (%d KB in %.2fs)", sp.KBPerSec, sp.Bytes/1024, sp.Seconds))
	}
	if st := r.Stability; st != nil {
		verdict := "held"
		if !st.Survived {
			verdict = "dropped"
		}
		lines = append(lines, fmt.Sprintf("hold:   %s %.0fs, %d pings, %d lost, drift %+.1f ms",
			verdict, st.Seconds, st.Pings, st.Lost, st.DriftMS))
	}
	if a := r.Audit; a != nil {
		if a.Masking != nil && a.Masking.Verdict != "not applicable" {
			line := "mask:   " + a.Masking.Verdict
			if a.Masking.Subject != "" {
				line += fmt.Sprintf(" (%s, issued by %s)", a.Masking.Subject, a.Masking.Issuer)
			} else if a.Masking.Error != "" {
				line += " (" + a.Masking.Error + ")"
			}
			lines = append(lines, line)
		}
		if a.AcceptsAnySecret != nil {
			verdict := "rejects a wrong secret"
			if *a.AcceptsAnySecret {
				verdict = "ACCEPTS ANY SECRET"
			}
			lines = append(lines, "secret: "+verdict)
		}
		if a.ConnLimit != nil {
			lines = append(lines, fmt.Sprintf("limit:  %d of %d parallel connections served",
				a.ConnLimit.Accepted, a.ConnLimit.Requested))
		}
	}
	return lines
}

func (s Style) Best(w io.Writer, results []checker.Result) {
	best, ok := BestOf(results)
	if !ok {
		return
	}
	where := ""
	if best.Geo != nil && best.Geo.Code != "" {
		where = " " + best.Geo.Flag() + " " + best.Geo.Code
	}
	fmt.Fprintf(w, "%s %s%s  %s  grade %s\n%s\n",
		s.paint(dim, "best:"),
		hostPort(best), where,
		formatLatency(best.LatencyMS),
		grade(best),
		s.paint(dim, "      "+best.Canonical),
	)
}

func BestOf(results []checker.Result) (checker.Result, bool) {
	var best checker.Result
	found := false
	for _, r := range results {
		if !r.Live() {
			continue
		}
		if !found || r.Score > best.Score || (r.Score == best.Score && r.LatencyMS < best.LatencyMS) {
			best, found = r, true
		}
	}
	return best, found
}

type Group struct {
	Label string
	Live  int
	Total int
}

func GroupBy(results []checker.Result, key func(checker.Result) string) []Group {
	index := map[string]*Group{}
	var order []string
	for _, r := range results {
		label := key(r)
		if label == "" {
			continue
		}
		if _, ok := index[label]; !ok {
			index[label] = &Group{Label: label}
			order = append(order, label)
		}
		index[label].Total++
		if r.Live() {
			index[label].Live++
		}
	}

	groups := make([]Group, 0, len(order))
	for _, label := range order {
		groups = append(groups, *index[label])
	}
	sort.Slice(groups, func(i, j int) bool {
		if groups[i].Live != groups[j].Live {
			return groups[i].Live > groups[j].Live
		}
		return groups[i].Total > groups[j].Total
	})
	return groups
}

func ByCountry(r checker.Result) string {
	if r.Geo == nil || r.Geo.Code == "" {
		return ""
	}
	return strings.TrimSpace(r.Geo.Flag() + " " + r.Geo.Code)
}

func ByASN(r checker.Result) string {
	if r.Geo == nil || r.Geo.ASN == 0 {
		return ""
	}
	name := r.Geo.Org
	if name == "" {
		name = r.Geo.ISP
	}
	return strings.TrimSpace(fmt.Sprintf("AS%d %s", r.Geo.ASN, name))
}

func ByErrorKind(r checker.Result) string {
	if r.Live() || r.ErrorKind == "" {
		return ""
	}
	return string(r.ErrorKind)
}

func (s Style) Breakdown(w io.Writer, results []checker.Result, limit int) {
	sections := []struct {
		title string
		key   func(checker.Result) string
		live  bool
	}{
		{"by country", ByCountry, true},
		{"by ASN", ByASN, true},
		{"failures", ByErrorKind, false},
	}

	for _, section := range sections {
		groups := GroupBy(results, section.key)
		if len(groups) == 0 {
			continue
		}
		if len(groups) > limit && limit > 0 {
			groups = groups[:limit]
		}

		parts := make([]string, 0, len(groups))
		for _, g := range groups {
			if section.live {
				parts = append(parts, fmt.Sprintf("%s %d/%d", g.Label, g.Live, g.Total))
			} else {
				parts = append(parts, fmt.Sprintf("%s %d", g.Label, g.Total))
			}
		}
		fmt.Fprintf(w, "%s %s\n", s.paint(dim, fmt.Sprintf("%-11s", section.title+":")), strings.Join(parts, " · "))
	}
}

func grade(r checker.Result) string {
	if r.Grade == "" {
		return " "
	}
	return r.Grade
}

func gradeColor(g string) string {
	switch g {
	case "A":
		return green
	case "B":
		return cyan
	case "C":
		return yellow
	default:
		return red
	}
}

func (s Style) Summary(w io.Writer, results []checker.Result, elapsed time.Duration) {
	sum := checker.Summarize(results)
	line := fmt.Sprintf("%d live, %d dead, %d invalid of %d in %s",
		sum.Live, sum.Dead, sum.Invalid, sum.Total, elapsed.Round(10*time.Millisecond))
	fmt.Fprintf(w, "\n%s %s\n", s.paint(dim, "summary:"), line)
}

func JSON(w io.Writer, results []checker.Result) error {
	payload := struct {
		GeneratedAt time.Time        `json:"generated_at"`
		Summary     checker.Summary  `json:"summary"`
		Results     []checker.Result `json:"results"`
	}{
		GeneratedAt: time.Now().UTC(),
		Summary:     checker.Summarize(results),
		Results:     results,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(payload)
}

func CSV(w io.Writer, results []checker.Result) error {
	out := csv.NewWriter(w)
	header := []string{
		"status", "grade", "score", "host", "port", "kind", "latency_ms",
		"connect_ms", "handshake_ms", "respq_ms", "ping_median_ms", "ping_jitter_ms", "ping_loss_pct",
		"route", "secret_mode", "sni", "country", "asn", "org",
		"exit_country", "speed_kb_s", "error_kind", "error", "link",
	}
	if err := out.Write(header); err != nil {
		return err
	}

	for _, r := range results {
		row := []string{
			string(r.Status),
			r.Grade,
			strconv.Itoa(r.Score),
			r.Host,
			strconv.Itoa(r.Port),
			string(r.Kind),
			formatLatency(r.LatencyMS),
			phase(r, func(t timingView) float64 { return t.connect }),
			phase(r, func(t timingView) float64 { return t.handshake }),
			phase(r, func(t timingView) float64 { return t.respq }),
			pingField(r, func(p pingView) float64 { return p.median }),
			pingField(r, func(p pingView) float64 { return p.jitter }),
			pingField(r, func(p pingView) float64 { return p.loss }),
			routeString(r),
			secretMode(r),
			secretDomain(r),
			geoField(r, func(g geoView) string { return g.code }),
			geoField(r, func(g geoView) string { return g.asn }),
			geoField(r, func(g geoView) string { return g.org }),
			exitCountry(r),
			speedField(r),
			string(r.ErrorKind),
			r.Error,
			r.Canonical,
		}
		if err := out.Write(row); err != nil {
			return err
		}
	}
	out.Flush()
	return out.Error()
}

func Links(w io.Writer, results []checker.Result) error {
	for _, r := range results {
		if r.Canonical == "" {
			continue
		}
		if _, err := fmt.Fprintln(w, r.Canonical); err != nil {
			return err
		}
	}
	return nil
}

type Writer func(io.Writer, []checker.Result) error

func ToFile(path string, results []checker.Result, write Writer) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	if err := write(file, results); err != nil {
		return err
	}
	return file.Sync()
}

func Filter(results []checker.Result, keep func(checker.Result) bool) []checker.Result {
	out := make([]checker.Result, 0, len(results))
	for _, r := range results {
		if keep(r) {
			out = append(out, r)
		}
	}
	return out
}

func hostPort(r checker.Result) string {
	if r.Host == "" {
		return r.Input
	}
	return fmt.Sprintf("%s:%d", r.Host, r.Port)
}

func attemptSuffix(r checker.Result) string {
	if r.Attempts <= 1 {
		return ""
	}
	return fmt.Sprintf(" (%d/%d)", r.Successes, r.Attempts)
}

func formatLatency(ms float64) string {
	if ms <= 0 {
		return ""
	}
	return strconv.FormatFloat(ms, 'f', 1, 64) + " ms"
}

func routeString(r checker.Result) string {
	if r.Route == nil {
		return ""
	}
	return r.Route.String()
}

func secretMode(r checker.Result) string {
	if r.Secret == nil {
		return ""
	}
	return string(r.Secret.Mode)
}

func secretDomain(r checker.Result) string {
	if r.Secret == nil {
		return ""
	}
	return r.Secret.Domain
}

type timingView struct{ connect, handshake, respq float64 }

func phase(r checker.Result, pick func(timingView) float64) string {
	if r.Timings == nil {
		return ""
	}
	value := pick(timingView{
		connect:   r.Timings.ConnectMS,
		handshake: r.Timings.HandshakeMS,
		respq:     r.Timings.RespQMS,
	})
	if value == 0 {
		return ""
	}
	return strconv.FormatFloat(value, 'f', 1, 64)
}

type pingView struct{ median, jitter, loss float64 }

func pingField(r checker.Result, pick func(pingView) float64) string {
	if r.Ping == nil || r.Ping.Sent == 0 {
		return ""
	}
	value := pick(pingView{
		median: r.Ping.MedianMS,
		jitter: r.Ping.JitterMS,
		loss:   r.Ping.LossPercent(),
	})
	return strconv.FormatFloat(value, 'f', 1, 64)
}

func exitCountry(r checker.Result) string {
	if r.Nearest == nil {
		return ""
	}
	return r.Nearest.Country
}

func speedField(r checker.Result) string {
	if r.Speed == nil || r.Speed.KBPerSec == 0 {
		return ""
	}
	return strconv.FormatFloat(r.Speed.KBPerSec, 'f', 1, 64)
}

type geoView struct{ code, asn, org string }

func geoField(r checker.Result, pick func(geoView) string) string {
	if r.Geo == nil {
		return ""
	}
	view := geoView{code: r.Geo.Code, org: r.Geo.Org}
	if r.Geo.ASN != 0 {
		view.asn = strconv.Itoa(r.Geo.ASN)
	}
	if view.org == "" {
		view.org = r.Geo.ISP
	}
	return pick(view)
}
