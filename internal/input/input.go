package input

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/yzewe/mtproto-checker/internal/proxy"
)

var linkPattern = regexp.MustCompile(`(?i)\b(?:tg://(?:webproxy|proxy|socks)|(?:https?://)?(?:t\.me|telegram\.me)/(?:webproxy|proxy|socks)|socks5://)[^\s"'<>]+`)

type Sources struct {
	Args  []string
	Files []string
	URLs  []string
	Stdin bool
}

func Collect(ctx context.Context, s Sources, httpTimeout time.Duration) ([]string, error) {

	collected := ExtractStrict(s.Args)

	var lines []string
	for _, path := range s.Files {
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		read, err := scan(file)
		file.Close()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		lines = append(lines, read...)
	}

	if s.Stdin {
		read, err := scan(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("stdin: %w", err)
		}
		lines = append(lines, read...)
	}

	client := &http.Client{Timeout: httpTimeout}
	for _, url := range s.URLs {
		read, err := fetch(ctx, client, url)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", url, err)
		}
		lines = append(lines, read...)
	}

	return Dedup(append(collected, Extract(lines)...)), nil
}

func scan(r io.Reader) ([]string, error) {
	var lines []string
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func fetch(ctx context.Context, client *http.Client, url string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %s", resp.Status)
	}
	return scan(io.LimitReader(resp.Body, 8<<20))
}

var hostPortPattern = regexp.MustCompile(`^\[?[a-zA-Z0-9_.:-]+\]?:\d{1,5}$`)

func Extract(lines []string) []string {
	var out []string
	for _, line := range lines {
		line = strings.TrimSpace(stripComment(line))
		if line == "" {
			continue
		}
		if found := linkPattern.FindAllString(line, -1); len(found) > 0 {
			for _, link := range found {
				out = append(out, unescape(strings.Trim(link, ".,;)")))
			}
			continue
		}
		if hostPortPattern.MatchString(line) {
			out = append(out, line)
		}
	}
	return out
}

func ExtractStrict(lines []string) []string {
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out
}

func stripComment(line string) string {
	trimmed := strings.TrimSpace(line)
	for _, marker := range []string{"#", "//", ";"} {
		if strings.HasPrefix(trimmed, marker) {
			return ""
		}
	}
	return line
}

func unescape(link string) string {
	replacer := strings.NewReplacer("&amp;", "&", "&#38;", "&", "&#61;", "=")
	for range 3 {
		unescaped := replacer.Replace(link)
		if unescaped == link {
			break
		}
		link = unescaped
	}
	return link
}

func Dedup(links []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(links))
	for _, link := range links {
		key := link
		if target, err := proxy.Parse(link); err == nil {
			key = target.Key()
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, link)
	}
	return out
}
