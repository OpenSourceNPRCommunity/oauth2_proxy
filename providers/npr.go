package providers

import (
	"fmt"
	"log"
	"net/http"
	"net/url"

	"github.com/bitly/oauth2_proxy/api"
)

type NPRProvider struct {
	*ProviderData
}

func NewNPRProvider(p *ProviderData) *NPRProvider {
	p.ProviderName = "NPR"
	if p.LoginURL == nil || p.LoginURL.String() == "" {
		p.LoginURL = &url.URL{
			Scheme: "https",
			Host:   "api.npr.org",
			Path:   "/authorization/v2/authorize",
		}
	}
	if p.RedeemURL == nil || p.RedeemURL.String() == "" {
		p.RedeemURL = &url.URL{
			Scheme: "https",
			Host:   "api.npr.org",
			Path:   "/authorization/v2/token",
		}
	}
	if p.ValidateURL == nil || p.ValidateURL.String() == "" {
		p.ValidateURL = &url.URL{
			Scheme: "https",
			Host:   "api.npr.org",
			Path:   "/identity/v2/user",
		}
	}
	if p.Scope == "" {
		p.Scope = "identity.readonly identity.write listening.readonly listening.write localactivation"
	}
	return &NPRProvider{ProviderData: p}
}

func (p *NPRProvider) getNPRHeader(access_token string) http.Header {
	header := make(http.Header)
	header.Set("Authorization", fmt.Sprintf("Bearer %s", access_token))
	return header
}

func (p *NPRProvider) GetEmailAddress(s *SessionState) (string, error) {

	req, err := http.NewRequest("GET", p.ValidateURL.String(), nil)
	if err != nil {
		log.Printf("failed building request %s", err)
		return "", err
	}

	req.Header = p.getNPRHeader(s.AccessToken)

	json, err := api.Request(req)
	if err != nil {
		log.Printf("failed making request %s", err)
		return "", err
	}
	return json.Get("attributes").Get("email").String()
}
