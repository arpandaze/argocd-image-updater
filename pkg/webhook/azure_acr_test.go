package webhook

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewAzureACRWebhook(t *testing.T) {
	secret := "test-secret"
	webhook := NewAzureACRWebhook(secret)

	if webhook == nil {
		t.Fatal("expected webhook to be non-nil")
	} else if webhook.secret != secret {
		t.Errorf("expected secret to be %q, got %q", secret, webhook.secret)
	}
}

func TestAzureACRWebhook_GetRegistryType(t *testing.T) {
	webhook := NewAzureACRWebhook("")
	registryType := webhook.GetRegistryType()

	expected := "azure-acr"
	if registryType != expected {
		t.Errorf("expected registry type to be %q, got %q", expected, registryType)
	}
}

func TestAzureACRWebhook_Validate(t *testing.T) {
	secret := "test-secret"
	webhook := NewAzureACRWebhook(secret)

	tests := []struct {
		name        string
		method      string
		secret      string
		noSecret    bool
		expectError bool
	}{
		{
			name:        "valid POST request with correct secret",
			method:      "POST",
			secret:      "test-secret",
			expectError: false,
		},
		{
			name:        "valid POST request without secret",
			method:      "POST",
			noSecret:    true,
			expectError: false,
		},
		{
			name:        "invalid HTTP method",
			method:      "GET",
			secret:      "test-secret",
			expectError: true,
		},
		{
			name:        "missing secret when secret is configured",
			method:      "POST",
			secret:      "",
			expectError: true,
		},
		{
			name:        "invalid secret",
			method:      "POST",
			secret:      "not-the-secret",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testWebhook := webhook
			if tt.noSecret {
				testWebhook = NewAzureACRWebhook("")
			}

			req := httptest.NewRequest(tt.method, "/webhook", nil)
			if tt.secret != "" {
				query := req.URL.Query()
				query.Set("secret", tt.secret)
				req.URL.RawQuery = query.Encode()
			}

			err := testWebhook.Validate(req)

			if tt.expectError && err == nil {
				t.Error("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("expected no error but got: %v", err)
			}
		})
	}
}

func TestAzureACRWebhook_Parse(t *testing.T) {
	tests := []struct {
		name                string
		payload             string
		queryRegistry       string
		expectedRepo        string
		expectedTag         string
		expectedRegistryURL string
		expectedDigest      string
		expectError         bool
	}{
		{
			name: "full ACR push event payload",
			payload: `{
				"id": "a72df132-21ba-4ce0-8610-b4e3b15dd08e",
				"timestamp": "2026-03-24T07:20:36.4650399Z",
				"action": "push",
				"target": {
					"mediaType": "application/vnd.oci.image.index.v1+json",
					"size": 856,
					"digest": "sha256:4ddbfc150c4df13c9b3f67843c16457cc24cb8ddd2063bbadb283a04e601aea6",
					"length": 856,
					"repository": "crixus-co-frontend",
					"tag": "ea2c8201"
				},
				"request": {
					"id": "98b4a798-4f78-4171-9867-ff493cfc702c",
					"host": "crixusimages.azurecr.io",
					"method": "PUT",
					"useragent": "buildkit/v0.28"
				}
			}`,
			expectedRepo:        "crixus-co-frontend",
			expectedTag:         "ea2c8201",
			expectedRegistryURL: "crixusimages.azurecr.io",
			expectedDigest:      "sha256:4ddbfc150c4df13c9b3f67843c16457cc24cb8ddd2063bbadb283a04e601aea6",
			expectError:         false,
		},
		{
			name: "query parameter overrides host",
			payload: `{
				"id": "test-id",
				"action": "push",
				"target": {
					"repository": "myapp",
					"tag": "v1.0",
					"digest": "sha256:abc123"
				},
				"request": {
					"host": "myregistry.azurecr.io"
				}
			}`,
			queryRegistry:       "custom-registry.example.com",
			expectedRepo:        "myapp",
			expectedTag:         "v1.0",
			expectedRegistryURL: "custom-registry.example.com",
			expectedDigest:      "sha256:abc123",
			expectError:         false,
		},
		{
			name: "missing host uses empty registry URL",
			payload: `{
				"id": "test-id",
				"action": "push",
				"target": {
					"repository": "myapp",
					"tag": "latest"
				},
				"request": {}
			}`,
			expectedRepo:        "myapp",
			expectedTag:         "latest",
			expectedRegistryURL: "",
			expectError:         false,
		},
		{
			name: "missing repository",
			payload: `{
				"id": "test-id",
				"action": "push",
				"target": {
					"tag": "v1.0"
				},
				"request": {
					"host": "myregistry.azurecr.io"
				}
			}`,
			expectError: true,
		},
		{
			name: "missing tag",
			payload: `{
				"id": "test-id",
				"action": "push",
				"target": {
					"repository": "myapp"
				},
				"request": {
					"host": "myregistry.azurecr.io"
				}
			}`,
			expectError: true,
		},
		{
			name:        "invalid JSON",
			payload:     `{"invalid": json}`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			webhook := NewAzureACRWebhook("")
			req := httptest.NewRequest("POST", "/webhook", strings.NewReader(tt.payload))

			if tt.queryRegistry != "" {
				query := req.URL.Query()
				query.Set("registry_url", tt.queryRegistry)
				req.URL.RawQuery = query.Encode()
			}

			event, err := webhook.Parse(req)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("expected no error but got: %v", err)
				return
			}

			if event == nil {
				t.Fatal("expected event to be non-nil")
			}
			if event.RegistryURL != tt.expectedRegistryURL {
				t.Errorf("expected registry URL to be %q, got %q", tt.expectedRegistryURL, event.RegistryURL)
			}
			if event.Repository != tt.expectedRepo {
				t.Errorf("expected repository to be %q, got %q", tt.expectedRepo, event.Repository)
			}
			if event.Tag != tt.expectedTag {
				t.Errorf("expected tag to be %q, got %q", tt.expectedTag, event.Tag)
			}
			if event.Digest != tt.expectedDigest {
				t.Errorf("expected digest to be %q, got %q", tt.expectedDigest, event.Digest)
			}
		})
	}
}
