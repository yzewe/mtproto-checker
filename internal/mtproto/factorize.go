package mtproto

import (
	"errors"
	"math/bits"
	mathrand "math/rand/v2"
)

func factorize(pq uint64) (p, q uint64, err error) {
	if pq%2 == 0 {
		return 2, pq / 2, nil
	}
	for attempt := range 8 {
		if factor := brent(pq, uint64(attempt)+1); factor > 1 && factor < pq {
			p, q = factor, pq/factor
			if p > q {
				p, q = q, p
			}
			return p, q, nil
		}
	}
	return 0, 0, errors.New("could not factorize pq")
}

const brentBudget = 1 << 20

func brent(n, seed uint64) uint64 {
	if n <= 3 {
		return n
	}
	steps := 0
	rng := mathrand.New(mathrand.NewPCG(seed, n))
	y := rng.Uint64()%(n-1) + 1
	c := rng.Uint64()%(n-1) + 1
	m := uint64(128)

	var g, r, q uint64 = 1, 1, 1
	var x, ys uint64

	for g == 1 {
		if steps > brentBudget {
			return 1
		}
		x = y
		for range r {
			y = next(y, c, n)
			steps++
		}

		for k := uint64(0); k < r && g == 1; k += m {
			ys = y
			for range min(m, r-k) {
				y = next(y, c, n)
				q = mulmod(q, diff(x, y), n)
				steps++
			}
			g = gcd(q, n)
		}
		r *= 2
	}

	if g == n {
		g = 1
		for g == 1 {
			if steps > brentBudget {
				return 1
			}
			ys = next(ys, c, n)
			g = gcd(diff(x, ys), n)
			steps++
		}
	}
	return g
}

func next(x, c, n uint64) uint64 { return addmod(mulmod(x, x, n), c, n) }

func diff(a, b uint64) uint64 {
	if a > b {
		return a - b
	}
	return b - a
}

func addmod(a, b, n uint64) uint64 {
	sum := a + b
	if sum < a || sum >= n {
		sum -= n
	}
	return sum
}

func mulmod(a, b, n uint64) uint64 {
	hi, lo := bits.Mul64(a, b)
	_, rem := bits.Div64(hi%n, lo, n)
	return rem
}

func gcd(a, b uint64) uint64 {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}
