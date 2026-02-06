package bws

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	sdk "github.com/bitwarden/sdk-go"
)

type provider struct {
	client bwsClient
	logger *slog.Logger
	orgID  string

	now func() time.Time

	cache bwsCache
	close sync.Once
}

type bwsCache struct {
	mu            sync.RWMutex
	expiresAt     time.Time
	projectByName map[string]string
	secretByProj  map[string]map[string]string // projectID -> keyName -> secretID
	cacheTTL      time.Duration
}

// New creates a Bitwarden Secrets Manager provider.
//
// It logs in using an access token and caches project/secret mappings for the configured TTL.
func New(cfg Config, logger *slog.Logger) (*provider, error) {
	cfg = cfg.withEnvDefaults()
	if err := cfg.validateForInit(); err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}

	var apiURL *string
	if strings.TrimSpace(cfg.APIURL) != "" {
		apiURL = &cfg.APIURL
	}
	var identityURL *string
	if strings.TrimSpace(cfg.IdentityURL) != "" {
		identityURL = &cfg.IdentityURL
	}

	client, err := sdk.NewBitwardenClient(apiURL, identityURL)
	if err != nil {
		return nil, fmt.Errorf("init bws client: %w", err)
	}

	var stateFile *string
	if strings.TrimSpace(cfg.StateFile) != "" {
		stateFile = &cfg.StateFile
	}
	if err := client.AccessTokenLogin(cfg.AccessToken, stateFile); err != nil {
		client.Close()
		return nil, fmt.Errorf("bws login failed: %w", err)
	}

	orgID := strings.TrimSpace(cfg.OrgID)
	if orgID == "" {
		orgID = strings.TrimSpace(os.Getenv("BWS_ORG_ID"))
	}

	p := &provider{
		client: client,
		logger: logger,
		orgID:  orgID,
		now:    time.Now,
		cache: bwsCache{
			projectByName: map[string]string{},
			secretByProj:  map[string]map[string]string{},
			cacheTTL:      cfg.CacheTTL,
		},
	}
	return p, nil
}

func (p *provider) Name() string { return "bws" }

func (p *provider) Resolve(ctx context.Context, ref string) (string, error) {
	trimmed := strings.TrimSpace(ref)
	if trimmed == "" {
		return "", errors.New("bws ref is empty")
	}

	if projectName, keyName, ok := parseProjectKeyRef(trimmed); ok {
		return p.resolveByProjectKey(ctx, projectName, keyName)
	}

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
	}

	secret, err := p.client.Secrets().Get(trimmed)
	if err != nil {
		return "", fmt.Errorf("bws get secret: %w", err)
	}
	return secret.Value, nil
}

func (p *provider) Close() error {
	p.close.Do(func() {
		if p.client != nil {
			p.client.Close()
		}
		p.cache.mu.Lock()
		p.cache.projectByName = map[string]string{}
		p.cache.secretByProj = map[string]map[string]string{}
		p.cache.expiresAt = time.Time{}
		p.cache.mu.Unlock()
	})
	return nil
}

func parseProjectKeyRef(ref string) (projectName string, keyName string, ok bool) {
	parts := strings.Split(ref, "/")
	if len(parts) != 4 {
		return "", "", false
	}
	if parts[0] != "project" || parts[2] != "key" {
		return "", "", false
	}
	if parts[1] == "" || parts[3] == "" {
		return "", "", false
	}
	return parts[1], parts[3], true
}

func (p *provider) resolveByProjectKey(ctx context.Context, projectName, keyName string) (string, error) {
	if strings.TrimSpace(p.orgID) == "" {
		if p.logger != nil {
			p.logger.Warn("bws organization id missing", "project", projectName, "key", keyName)
		}
		return "", errors.New("bws organization id is required for project/key lookup")
	}

	if err := p.ensureCache(ctx); err != nil {
		return "", err
	}

	p.cache.mu.RLock()
	projectID, ok := p.cache.projectByName[projectName]
	if !ok {
		p.cache.mu.RUnlock()
		if p.logger != nil {
			p.logger.Warn("bws project not found", "project", projectName, "key", keyName)
		}
		return "", fmt.Errorf("bws project %q not found", projectName)
	}
	secrets := p.cache.secretByProj[projectID]
	secretID, ok := secrets[keyName]
	p.cache.mu.RUnlock()
	if !ok {
		if p.logger != nil {
			p.logger.Warn("bws secret not found", "project", projectName, "key", keyName)
		}
		return "", fmt.Errorf("bws secret %q not found in project %q", keyName, projectName)
	}

	secret, err := p.client.Secrets().Get(secretID)
	if err != nil {
		return "", fmt.Errorf("bws get secret: %w", err)
	}
	return secret.Value, nil
}

func (p *provider) ensureCache(ctx context.Context) error {
	if p.cache.cacheTTL <= 0 {
		return p.refreshCache(ctx)
	}

	now := p.now
	if now == nil {
		now = time.Now
	}

	p.cache.mu.RLock()
	if now().Before(p.cache.expiresAt) && len(p.cache.projectByName) > 0 {
		p.cache.mu.RUnlock()
		return nil
	}
	p.cache.mu.RUnlock()

	return p.refreshCache(ctx)
}

func (p *provider) refreshCache(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	projects, err := p.client.Projects().List(p.orgID)
	if err != nil {
		return fmt.Errorf("bws list projects: %w", err)
	}
	secretIDs, err := p.client.Secrets().List(p.orgID)
	if err != nil {
		return fmt.Errorf("bws list secrets: %w", err)
	}

	ids := make([]string, 0, len(secretIDs.Data))
	for _, secret := range secretIDs.Data {
		ids = append(ids, secret.ID)
	}

	secrets := &sdk.SecretsResponse{}
	if len(ids) > 0 {
		secrets, err = p.client.Secrets().GetByIDS(ids)
		if err != nil {
			return fmt.Errorf("bws get secrets: %w", err)
		}
	}

	projectByName := make(map[string]string, len(projects.Data))
	for _, project := range projects.Data {
		projectByName[project.Name] = project.ID
	}

	secretByProj := make(map[string]map[string]string)
	for _, secret := range secrets.Data {
		if secret.ProjectID == nil {
			continue
		}
		projectID := *secret.ProjectID
		if secretByProj[projectID] == nil {
			secretByProj[projectID] = make(map[string]string)
		}
		secretByProj[projectID][secret.Key] = secret.ID
	}

	now := p.now
	if now == nil {
		now = time.Now
	}

	p.cache.mu.Lock()
	p.cache.projectByName = projectByName
	p.cache.secretByProj = secretByProj
	p.cache.expiresAt = now().Add(p.cache.cacheTTL)
	p.cache.mu.Unlock()

	return nil
}
