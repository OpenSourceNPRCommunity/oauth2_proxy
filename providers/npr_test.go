package providers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func testNPRProvider(hostname string) *NPRProvider {
	p := NewNPRProvider(
		&ProviderData{
			ProviderName: "",
			LoginURL:     &url.URL{},
			RedeemURL:    &url.URL{},
			ProfileURL:   &url.URL{},
			ValidateURL:  &url.URL{},
			Scope:        ""})
	if hostname != "" {
		updateURL(p.Data().LoginURL, hostname)
		updateURL(p.Data().RedeemURL, hostname)
		updateURL(p.Data().ProfileURL, hostname)
		updateURL(p.Data().ValidateURL, hostname)
	}
	return p
}

func testNPRBackend(payload string) *httptest.Server {
	path := "/identity/v2/user"
	query := "access_token=imaginary_access_token"

	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			url := r.URL
			if url.Path != path || url.RawQuery != query {
				w.WriteHeader(404)
			} else {
				w.WriteHeader(200)
				w.Write([]byte(payload))
			}
		}))
}

func TestNPRProviderDefaults(t *testing.T) {
	p := testNPRProvider("")
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "NPR", p.Data().ProviderName)
	assert.Equal(t, "https://api.npr.org/authorization/v2/authorize",
		p.Data().LoginURL.String())
	assert.Equal(t, "https://api.npr.org/authorization/v2/token",
		p.Data().RedeemURL.String())
	assert.Equal(t, "https://api.npr.org/identity/v2/user",
		p.Data().ValidateURL.String())
	assert.Equal(t, "identity.readonly identity.write listening.readonly listening.write localactivation", p.Data().Scope)
}

func TestNPRProviderOverrides(t *testing.T) {
	p := NewNPRProvider(
		&ProviderData{
			LoginURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/oauth/auth"},
			RedeemURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/oauth/token"},
			ValidateURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/identity/v4/user"},
			Scope: "random"})
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "NPR", p.Data().ProviderName)
	assert.Equal(t, "https://example.com/oauth/auth",
		p.Data().LoginURL.String())
	assert.Equal(t, "https://example.com/oauth/token",
		p.Data().RedeemURL.String())
	assert.Equal(t, "https://example.com/identity/v4/user",
		p.Data().ValidateURL.String())
	assert.Equal(t, "random", p.Data().Scope)
}

func TestNPRProviderGetEmailAddress(t *testing.T) {
	s := `{"attributes":{"email":"michael.bland@gsa.gov"}}`
	b := testNPRBackend(s)
	defer b.Close()

	b_url, _ := url.Parse(b.URL)
	p := testNPRProvider(b_url.Host)

	session := &SessionState{AccessToken: "imaginary_access_token"}
	email, err := p.GetEmailAddress(session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "michael.bland@gsa.gov", email)
}

// Note that trying to trigger the "failed building request" case is not
// practical, since the only way it can fail is if the URL fails to parse.
func TestNPRProviderGetEmailAddressFailedRequest(t *testing.T) {
	b := testNPRBackend("unused payload")
	defer b.Close()

	b_url, _ := url.Parse(b.URL)
	p := testNPRProvider(b_url.Host)

	// We'll trigger a request failure by using an unexpected access
	// token. Alternatively, we could allow the parsing of the payload as
	// JSON to fail.
	session := &SessionState{AccessToken: "unexpected_access_token"}
	email, err := p.GetEmailAddress(session)
	assert.NotEqual(t, nil, err)
	assert.Equal(t, "", email)
}

func TestNPRProviderGetEmailAddressEmailNotPresentInPayload(t *testing.T) {
	b := testNPRBackend("{\"foo\": \"bar\"}")
	defer b.Close()

	b_url, _ := url.Parse(b.URL)
	p := testNPRProvider(b_url.Host)

	session := &SessionState{AccessToken: "imaginary_access_token"}
	email, err := p.GetEmailAddress(session)
	assert.NotEqual(t, nil, err)
	assert.Equal(t, "", email)
}
