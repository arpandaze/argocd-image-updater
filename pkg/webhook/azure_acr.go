package webhook

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/argoproj-labs/argocd-image-updater/pkg/argocd"
)

// AzureACRWebhook handles Azure Container Registry webhook events
type AzureACRWebhook struct {
	secret string
}

// NewAzureACRWebhook creates a new Azure ACR webhook handler
func NewAzureACRWebhook(secret string) *AzureACRWebhook {
	return &AzureACRWebhook{
		secret: secret,
	}
}

// GetRegistryType returns the registry type this handler supports
func (a *AzureACRWebhook) GetRegistryType() string {
	return "azure-acr"
}

// Validate validates the Azure ACR webhook payload
func (a *AzureACRWebhook) Validate(r *http.Request) error {
	if r.Method != http.MethodPost {
		return fmt.Errorf("invalid HTTP method: %s", r.Method)
	}

	// If secret is configured, validate it from query parameter
	if a.secret != "" {
		secret := r.URL.Query().Get("secret")
		if secret == "" {
			return fmt.Errorf("missing webhook secret")
		}

		if subtle.ConstantTimeCompare([]byte(secret), []byte(a.secret)) != 1 {
			return fmt.Errorf("invalid webhook secret")
		}
	}

	return nil
}

// Parse processes the Azure ACR webhook payload and returns a WebhookEvent
func (a *AzureACRWebhook) Parse(r *http.Request) (*argocd.WebhookEvent, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read request body: %w", err)
	}

	// Azure ACR payload structure for push events
	var payload struct {
		ID        string `json:"id"`
		Timestamp string `json:"timestamp"`
		Action    string `json:"action"`
		Target    struct {
			MediaType  string `json:"mediaType"`
			Size       int    `json:"size"`
			Digest     string `json:"digest"`
			Length     int    `json:"length"`
			Repository string `json:"repository"`
			Tag        string `json:"tag"`
		} `json:"target"`
		Request struct {
			ID        string `json:"id"`
			Host      string `json:"host"`
			Method    string `json:"method"`
			UserAgent string `json:"useragent"`
		} `json:"request"`
	}

	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("failed to parse webhook payload: %w", err)
	}

	if payload.Target.Repository == "" {
		return nil, fmt.Errorf("repository name not found in webhook payload")
	}

	if payload.Target.Tag == "" {
		return nil, fmt.Errorf("tag not found in webhook payload")
	}

	// ACR registry URL is extracted from the request host field
	// Override with query parameter if provided
	registryURL := ""
	if queryRegistry := r.URL.Query().Get("registry_url"); queryRegistry != "" {
		registryURL = queryRegistry
	} else if payload.Request.Host != "" {
		registryURL = payload.Request.Host
	}

	return &argocd.WebhookEvent{
		RegistryURL: registryURL,
		Repository:  payload.Target.Repository,
		Tag:         payload.Target.Tag,
		Digest:      payload.Target.Digest,
	}, nil
}
