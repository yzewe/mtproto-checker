package mtproto

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/yzewe/mtproto-checker/internal/proxy"
	"github.com/yzewe/mtproto-checker/internal/webproxy"
)

// probeWebProxy checks a Telegram WEB proxy. The relay hands our bytes to a
// stock MTProxy, so the same obfuscated handshake runs unchanged on top of the
// carrier.
func (c *Checker) probeWebProxy(ctx context.Context, t *proxy.Target) (Outcome, error) {
	order := []transport{intermediate, abridged, paddedIntermediate}
	if t.Mode() == proxy.ModeSecure {
		order = []transport{paddedIntermediate, intermediate, abridged}
	}

	// Every attempt costs a fresh relay session, so keep the list short.
	limit := min(len(order), 2)

	var problems []string
	var lastErr error
	for _, tr := range order[:limit] {
		outcome, err := c.attemptWebProxy(ctx, t, candidate{dc: dcOrder[0], tr: tr})
		if err == nil {
			return outcome, nil
		}
		lastErr = err

		var probeErr *Error
		if errors.As(err, &probeErr) && probeErr.Stage != StageProtocol {
			return Outcome{}, err
		}
		problems = append(problems, fmt.Sprintf("%s: %v", tr.name, err))
		if ctx.Err() != nil {
			return Outcome{}, fail(StageDial, ctx.Err())
		}
	}
	return Outcome{}, failAs(StageProtocol, KindOf(lastErr), errors.New(summarize(problems, 2)))
}

func (c *Checker) attemptWebProxy(ctx context.Context, t *proxy.Target, cand candidate) (Outcome, error) {
	started := time.Now()
	carrier, err := webproxy.Dial(ctx, webproxy.Options{
		Host:    t.Host,
		Secret:  t.SecretBytes(),
		Timeout: c.Timeout,
	})
	if err != nil {
		return Outcome{}, webProxyError(err)
	}
	defer carrier.Close()

	handshake := time.Since(started)
	carrier.SetDeadline(time.Now().Add(c.budget()))

	outcome := Outcome{
		Route: Route{
			Protocol:  "webproxy",
			DC:        cand.dc,
			Transport: cand.tr.name,
			Via:       carrier.Mode(),
			Depth:     c.depth(),
		},
		Timings: Timings{HandshakeMS: ms(handshake)},
	}

	stages, err := c.handshake(nil, carrier, t.SecretKey(), cand)
	if err != nil {
		return Outcome{}, err
	}

	outcome.Route.ServerTimeSkew = stages.skew
	outcome.Timings.RespQMS = ms(stages.respq)
	outcome.Ping = stages.ping
	outcome.Nearest = stages.nearest
	outcome.Config = stages.config
	outcome.Speed = stages.speed
	outcome.Stability = stages.stability
	return outcome, nil
}

// webProxyError maps a carrier failure onto the checker's stages: a rejected
// capability is as final as a rejected MTProto secret.
func webProxyError(err error) error {
	var carrierErr *webproxy.Error
	if !errors.As(err, &carrierErr) {
		return fail(StageDial, err)
	}

	switch carrierErr.Stage {
	case webproxy.StageBridge:
		if isSecretRejection(carrierErr) {
			return failAs(StageHandshake, KindSecretRejected, err)
		}
		return fail(StageDial, err)
	case webproxy.StageSession:
		return failAs(StageHandshake, KindHandshake, err)
	default:
		return fail(StageProtocol, err)
	}
}

func isSecretRejection(err error) bool {
	return err != nil && strings.Contains(err.Error(), "secret does not match")
}
