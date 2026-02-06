package bws

import (
	"context"
	"sync"
	"testing"
	"time"

	sdk "github.com/bitwarden/sdk-go"
)

type fakeClient struct {
	secrets  *fakeSecrets
	projects *fakeProjects
	closed   bool
	mu       sync.Mutex
}

func (c *fakeClient) Secrets() sdk.SecretsInterface  { return c.secrets }
func (c *fakeClient) Projects() sdk.ProjectsInterface { return c.projects }
func (c *fakeClient) Close() {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
}

type fakeSecrets struct {
	getCalls      []string
	listCalls     []string
	getByIDsCalls [][]string

	getResp      map[string]*sdk.SecretResponse
	listResp     *sdk.SecretIdentifiersResponse
	getByIDsResp *sdk.SecretsResponse
}

func (s *fakeSecrets) Create(string, string, string, string, []string) (*sdk.SecretResponse, error) {
	panic("not used")
}
func (s *fakeSecrets) List(orgID string) (*sdk.SecretIdentifiersResponse, error) {
	s.listCalls = append(s.listCalls, orgID)
	if s.listResp == nil {
		return &sdk.SecretIdentifiersResponse{}, nil
	}
	return s.listResp, nil
}
func (s *fakeSecrets) Get(id string) (*sdk.SecretResponse, error) {
	s.getCalls = append(s.getCalls, id)
	if s.getResp != nil {
		if resp, ok := s.getResp[id]; ok {
			return resp, nil
		}
	}
	return &sdk.SecretResponse{ID: id, Value: ""}, nil
}
func (s *fakeSecrets) GetByIDS(ids []string) (*sdk.SecretsResponse, error) {
	cp := make([]string, len(ids))
	copy(cp, ids)
	s.getByIDsCalls = append(s.getByIDsCalls, cp)
	if s.getByIDsResp == nil {
		return &sdk.SecretsResponse{}, nil
	}
	return s.getByIDsResp, nil
}
func (s *fakeSecrets) Update(string, string, string, string, string, []string) (*sdk.SecretResponse, error) {
	panic("not used")
}
func (s *fakeSecrets) Delete([]string) (*sdk.SecretsDeleteResponse, error) { panic("not used") }
func (s *fakeSecrets) Sync(string, *time.Time) (*sdk.SecretsSyncResponse, error) {
	panic("not used")
}

type fakeProjects struct {
	listCalls []string
	listResp  *sdk.ProjectsResponse
}

func (p *fakeProjects) Create(string, string) (*sdk.ProjectResponse, error) { panic("not used") }
func (p *fakeProjects) List(orgID string) (*sdk.ProjectsResponse, error) {
	p.listCalls = append(p.listCalls, orgID)
	if p.listResp == nil {
		return &sdk.ProjectsResponse{}, nil
	}
	return p.listResp, nil
}
func (p *fakeProjects) Get(string) (*sdk.ProjectResponse, error) { panic("not used") }
func (p *fakeProjects) Update(string, string, string) (*sdk.ProjectResponse, error) {
	panic("not used")
}
func (p *fakeProjects) Delete([]string) (*sdk.ProjectsDeleteResponse, error) { panic("not used") }

func TestBWSProvider_ResolveBySecretID_UsesClientGet(t *testing.T) {
	ctx := context.Background()

	secrets := &fakeSecrets{
		getResp: map[string]*sdk.SecretResponse{
			"secret-id": {ID: "secret-id", Value: "s3cr3t"},
		},
	}
	client := &fakeClient{secrets: secrets, projects: &fakeProjects{}}

	p := &provider{
		client: client,
		orgID:  "",
		now:    time.Now,
		cache: bwsCache{
			projectByName: map[string]string{},
			secretByProj:  map[string]map[string]string{},
			cacheTTL:      10 * time.Minute,
		},
	}

	got, err := p.Resolve(ctx, "secret-id")
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}
	if got != "s3cr3t" {
		t.Fatalf("unexpected value: %q", got)
	}
	if len(secrets.getCalls) != 1 || secrets.getCalls[0] != "secret-id" {
		t.Fatalf("expected Get(secret-id) to be called, got: %#v", secrets.getCalls)
	}
}

func TestBWSProvider_ProjectKeyLookup_UsesCacheAndGet(t *testing.T) {
	ctx := context.Background()

	projectID := "p1"
	secretID := "s1"
	keyName := "SUPABASE_ACCESS_TOKEN"

	secrets := &fakeSecrets{
		listResp: &sdk.SecretIdentifiersResponse{Data: []sdk.SecretIdentifierResponse{
			{ID: secretID, Key: keyName, OrganizationID: "org"},
		}},
		getByIDsResp: &sdk.SecretsResponse{Data: []sdk.SecretResponse{
			{ID: secretID, Key: keyName, ProjectID: &projectID, Value: "ignored"},
		}},
		getResp: map[string]*sdk.SecretResponse{
			secretID: {ID: secretID, Value: "token"},
		},
	}
	projects := &fakeProjects{
		listResp: &sdk.ProjectsResponse{Data: []sdk.ProjectResponse{
			{ID: projectID, Name: "dotenv", OrganizationID: "org"},
		}},
	}
	client := &fakeClient{secrets: secrets, projects: projects}

	now := time.Date(2026, 2, 6, 12, 0, 0, 0, time.UTC)
	p := &provider{
		client: client,
		orgID:  "org",
		now:    func() time.Time { return now },
		cache: bwsCache{
			projectByName: map[string]string{},
			secretByProj:  map[string]map[string]string{},
			cacheTTL:      10 * time.Minute,
		},
	}

	got, err := p.Resolve(ctx, "project/dotenv/key/"+keyName)
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}
	if got != "token" {
		t.Fatalf("unexpected value: %q", got)
	}
	if len(projects.listCalls) != 1 {
		t.Fatalf("expected Projects().List to be called once, got: %#v", projects.listCalls)
	}
	if len(secrets.listCalls) != 1 {
		t.Fatalf("expected Secrets().List to be called once, got: %#v", secrets.listCalls)
	}
	if len(secrets.getByIDsCalls) != 1 {
		t.Fatalf("expected Secrets().GetByIDS to be called once, got: %#v", secrets.getByIDsCalls)
	}

	// Second call should hit cache and only call Get(secretID).
	got, err = p.Resolve(ctx, "project/dotenv/key/"+keyName)
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}
	if got != "token" {
		t.Fatalf("unexpected value: %q", got)
	}
	if len(projects.listCalls) != 1 || len(secrets.listCalls) != 1 || len(secrets.getByIDsCalls) != 1 {
		t.Fatalf("expected cache to prevent refresh; calls: projects=%d secrets.list=%d secrets.getByIds=%d",
			len(projects.listCalls), len(secrets.listCalls), len(secrets.getByIDsCalls))
	}
}

func TestBWSProvider_CacheTTL_RefreshesAfterExpiry(t *testing.T) {
	ctx := context.Background()

	projectID := "p1"
	secretID := "s1"
	keyName := "TAVILY_API_KEY"

	secrets := &fakeSecrets{
		listResp: &sdk.SecretIdentifiersResponse{Data: []sdk.SecretIdentifierResponse{
			{ID: secretID, Key: keyName, OrganizationID: "org"},
		}},
		getByIDsResp: &sdk.SecretsResponse{Data: []sdk.SecretResponse{
			{ID: secretID, Key: keyName, ProjectID: &projectID, Value: "ignored"},
		}},
		getResp: map[string]*sdk.SecretResponse{
			secretID: {ID: secretID, Value: "token"},
		},
	}
	projects := &fakeProjects{
		listResp: &sdk.ProjectsResponse{Data: []sdk.ProjectResponse{
			{ID: projectID, Name: "dotenv", OrganizationID: "org"},
		}},
	}
	client := &fakeClient{secrets: secrets, projects: projects}

	var nowMu sync.Mutex
	now := time.Date(2026, 2, 6, 12, 0, 0, 0, time.UTC)
	nowFn := func() time.Time {
		nowMu.Lock()
		defer nowMu.Unlock()
		return now
	}

	p := &provider{
		client: client,
		orgID:  "org",
		now:    nowFn,
		cache: bwsCache{
			projectByName: map[string]string{},
			secretByProj:  map[string]map[string]string{},
			cacheTTL:      10 * time.Minute,
		},
	}

	if _, err := p.Resolve(ctx, "project/dotenv/key/"+keyName); err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}
	if len(projects.listCalls) != 1 {
		t.Fatalf("expected one refresh, got %d", len(projects.listCalls))
	}

	nowMu.Lock()
	now = now.Add(11 * time.Minute)
	nowMu.Unlock()

	if _, err := p.Resolve(ctx, "project/dotenv/key/"+keyName); err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}
	if len(projects.listCalls) != 2 {
		t.Fatalf("expected refresh after TTL, got %d", len(projects.listCalls))
	}
}

func TestBWSProvider_MissingOrgID_ErrorsOnProjectKeyLookup(t *testing.T) {
	ctx := context.Background()

	secrets := &fakeSecrets{}
	projects := &fakeProjects{}
	client := &fakeClient{secrets: secrets, projects: projects}

	p := &provider{
		client: client,
		orgID:  "",
		now:    time.Now,
		cache: bwsCache{
			projectByName: map[string]string{},
			secretByProj:  map[string]map[string]string{},
			cacheTTL:      10 * time.Minute,
		},
	}

	_, err := p.Resolve(ctx, "project/dotenv/key/EXAMPLE")
	if err == nil {
		t.Fatalf("expected error")
	}
	if len(projects.listCalls) != 0 || len(secrets.listCalls) != 0 {
		t.Fatalf("expected no list calls when org id missing, got projects=%d secrets=%d", len(projects.listCalls), len(secrets.listCalls))
	}
}

