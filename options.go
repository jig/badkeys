package badkeys

// Option configures a check operation.
type Option func(*config)

type config struct {
	checks     []string
	keyRecover bool
}

func newConfig(opts []Option) config {
	c := config{checks: DefaultChecks()}
	for _, o := range opts {
		o(&c)
	}
	return c
}

// WithChecks restricts the operation to the named checks. Unknown names are
// ignored. If not given, the default checks are used.
func WithChecks(names ...string) Option {
	return func(c *config) { c.checks = names }
}

// WithKeyRecover enables recovery of private key material when a check factors
// the modulus or recovers the private exponent.
func WithKeyRecover() Option {
	return func(c *config) { c.keyRecover = true }
}
