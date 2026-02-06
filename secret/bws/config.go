package bws

import (
	"errors"
	"os"
	"strings"
	"time"
)

// Config configures the Bitwarden Secrets Manager provider.
type Config struct {
	AccessToken string
	OrgID       string
	APIURL      string
	IdentityURL string
	StateFile   string
	CacheTTL    time.Duration
}

func (c Config) withEnvDefaults() Config {
	out := c
	if strings.TrimSpace(out.AccessToken) == "" {
		out.AccessToken = strings.TrimSpace(os.Getenv("BWS_ACCESS_TOKEN"))
	}
	if strings.TrimSpace(out.OrgID) == "" {
		out.OrgID = strings.TrimSpace(os.Getenv("BWS_ORG_ID"))
	}
	if out.CacheTTL == 0 {
		out.CacheTTL = 10 * time.Minute
	}
	return out
}

func (c Config) validateForInit() error {
	if strings.TrimSpace(c.AccessToken) == "" {
		return errors.New("bws access token is required")
	}
	if c.CacheTTL < 0 {
		return errors.New("bws cache_ttl cannot be negative")
	}
	return nil
}
