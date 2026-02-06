package bws

import (
	"errors"
	"fmt"
	"time"

	"github.com/jonwraymond/toolops/secret"
)

// Register registers the BWS secret provider factory under the name "bws".
func Register(reg *secret.Registry) error {
	if reg == nil {
		return errors.New("secret registry is required")
	}
	return reg.Register("bws", func(cfg map[string]any) (secret.Provider, error) {
		parsed, err := configFromMap(cfg)
		if err != nil {
			return nil, err
		}
		return New(parsed, nil)
	})
}

func configFromMap(cfg map[string]any) (Config, error) {
	var out Config
	if cfg == nil {
		return out, nil
	}

	out.AccessToken = stringVal(cfg, "access_token")
	out.OrgID = stringVal(cfg, "organization_id")
	out.APIURL = stringVal(cfg, "api_url")
	out.IdentityURL = stringVal(cfg, "identity_url")
	out.StateFile = stringVal(cfg, "state_file")

	if v, ok := cfg["cache_ttl"]; ok {
		d, err := durationVal(v)
		if err != nil {
			return Config{}, fmt.Errorf("invalid cache_ttl: %w", err)
		}
		out.CacheTTL = d
	}

	return out, nil
}

func stringVal(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	default:
		return fmt.Sprint(t)
	}
}

func durationVal(v any) (time.Duration, error) {
	switch t := v.(type) {
	case time.Duration:
		return t, nil
	case string:
		if t == "" {
			return 0, nil
		}
		return time.ParseDuration(t)
	default:
		return 0, fmt.Errorf("expected duration string, got %T", v)
	}
}

