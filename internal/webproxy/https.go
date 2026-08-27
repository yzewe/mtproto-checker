package webproxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// httpCarrier implements the serialized HTTPS and the per-lane HTTPS modes.
// Both use the same endpoints; lanes only add a header and keep their sequence
// counters separately, which for a single stream amounts to the same thing.
type httpCarrier struct {
	c      *Carrier
	upSeq  int
	cursor string
}

func newHTTPCarrier(c *Carrier) *httpCarrier {
	return &httpCarrier{c: c, cursor: "0"}
}

func (h *httpCarrier) send(ctx context.Context, frames []byte) error {
	if len(frames) == 0 {
		return nil
	}
	h.upSeq++

	// A 503 means the relay could not take the batch yet and the sequence
	// stays uncommitted, so the identical body has to be repeated.
	for attempt := range 4 {
		req, err := h.c.newAPIRequest(ctx, http.MethodPost, "/api/v1/up", h.c.session, frames)
		if err != nil {
			return err
		}
		req.Header.Set("X-Up-Seq", strconv.Itoa(h.upSeq))
		if h.c.lanes {
			req.Header.Set("X-Lane-ID", strconv.Itoa(streamID))
		}

		resp, err := h.c.client.Do(req)
		if err != nil {
			return err
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()

		switch resp.StatusCode {
		case http.StatusNoContent, http.StatusOK:
			return nil
		case http.StatusServiceUnavailable:
			if !sleepRetry(ctx, resp.Header.Get("Retry-After"), attempt) {
				return ctx.Err()
			}
		default:
			return fmt.Errorf("uplink answered %s: %w", resp.Status, errUnexpectedStatus)
		}
	}
	return fmt.Errorf("relay kept refusing the uplink batch: %w", errUnexpectedStatus)
}

func (h *httpCarrier) receive(ctx context.Context) ([]byte, error) {
	req, err := h.c.newAPIRequest(ctx, http.MethodPost, "/api/v1/down", h.c.session, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Down-Cursor", h.cursor)
	if h.c.lanes {
		req.Header.Set("X-Lane-ID", strconv.Itoa(streamID))
	}

	resp, err := h.c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, err
	}
	if cursor := resp.Header.Get("X-Down-Cursor"); cursor != "" {
		h.cursor = cursor
	}
	if resp.Header.Get("X-Lane-Closed") == "1" {
		h.c.eof = true
	}

	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent:
		return body, nil
	case http.StatusServiceUnavailable:
		if !sleepRetry(ctx, resp.Header.Get("Retry-After"), 0) {
			return nil, ctx.Err()
		}
		return nil, nil
	default:
		return nil, fmt.Errorf("downlink answered %s: %w", resp.Status, errUnexpectedStatus)
	}
}

func (h *httpCarrier) close() {}

// sleepRetry honours Retry-After, falling back to a short backoff. It reports
// whether the wait finished before the context expired.
func sleepRetry(ctx context.Context, retryAfter string, attempt int) bool {
	delay := time.Duration(attempt+1) * 250 * time.Millisecond
	if seconds, err := strconv.Atoi(retryAfter); err == nil && seconds > 0 && seconds <= 5 {
		delay = time.Duration(seconds) * time.Second
	}

	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func insecureTLS() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true}
}
