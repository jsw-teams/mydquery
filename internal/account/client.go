package account

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type Config struct {
	Enabled      bool     `yaml:"enabled"`
	ClientName   string   `yaml:"client_name"`
	ClientID     string   `yaml:"client_id"`
	APIKey       string   `yaml:"api_key"`
	BaseURL      string   `yaml:"base_url"`
	LoginURL     string   `yaml:"login_url"`
	RedirectURI  string   `yaml:"redirect_uri"`
	Scopes       []string `yaml:"scopes"`
}

type User struct {
	ID                 string         `json:"id"`
	Email              string         `json:"email"`
	DisplayName        string         `json:"displayName"`
	Status             string         `json:"status"`
	Role               string         `json:"role"`
	UserType           string         `json:"userType"`
	MustChangePassword bool           `json:"mustChangePassword"`
	Capabilities       map[string]any `json:"capabilities"`
	Metadata           map[string]any `json:"metadata"`
}

type meResponse struct {
	User User `json:"user"`
}

type LoginResult struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expiresAt"`
	User      User   `json:"user"`
}

type Client struct {
	baseURL    string
	httpClient *http.Client
}

func NewClient(cfg Config) *Client {
	baseURL := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if baseURL == "" {
		baseURL = "https://gateway.js.gripe/api/v1/myaccount"
	}
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

func (c *Client) Login(ctx context.Context, email, password string) (LoginResult, error) {
	var zero LoginResult
	body, err := json.Marshal(map[string]string{
		"email":    strings.TrimSpace(email),
		"password": password,
	})
	if err != nil {
		return zero, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/auth/login", bytes.NewReader(body))
	if err != nil {
		return zero, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return zero, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return zero, fmt.Errorf("account service returned %d", resp.StatusCode)
	}

	var out LoginResult
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return zero, err
	}
	if strings.TrimSpace(out.Token) == "" || strings.TrimSpace(out.User.ID) == "" {
		return zero, fmt.Errorf("account login response missing token or user id")
	}
	return out, nil
}

func (c *Client) Me(ctx context.Context, token string) (User, error) {
	var zero User
	token = strings.TrimSpace(token)
	if token == "" {
		return zero, fmt.Errorf("missing account token")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/me", nil)
	if err != nil {
		return zero, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return zero, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return zero, fmt.Errorf("account service returned %d", resp.StatusCode)
	}

	var out meResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return zero, err
	}
	if strings.TrimSpace(out.User.ID) == "" {
		return zero, fmt.Errorf("account response missing user id")
	}
	return out.User, nil
}

func BearerToken(r *http.Request) string {
	value := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(value, "Bearer ") {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(value, "Bearer "))
}
