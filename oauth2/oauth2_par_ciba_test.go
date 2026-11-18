// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	hydra "github.com/ory/hydra-client-go/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/hydra/v2/client"
	"github.com/ory/hydra/v2/driver"
	"github.com/ory/hydra/v2/fosite"
	"github.com/ory/hydra/v2/internal/testhelpers"
	"github.com/ory/hydra/v2/oauth2"
	"github.com/ory/x/configx"
)

func TestPushedAuthorizationRequest(t *testing.T) {
	ctx := t.Context()
	reg := testhelpers.NewRegistryMemory(t, driver.WithConfigOptions(configx.WithValues(map[string]any{
		"urls.login": "https://login.example/",
	})))
	publicTS, _ := testhelpers.NewOAuth2Server(ctx, t, reg)
	_, conf := newOAuth2Client(t, reg, "https://client.example/callback", withScope("openid offline"))

	form := url.Values{
		"client_id":     {conf.ClientID},
		"response_type": {"code"},
		"redirect_uri":  {conf.RedirectURL},
		"scope":         {"openid offline"},
		"state":         {"par-state"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, publicTS.URL+oauth2.PARPath, strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(conf.ClientID, conf.ClientSecret)

	res, err := publicTS.Client().Do(req)
	require.NoError(t, err)
	defer res.Body.Close() //nolint:errcheck
	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	require.Equalf(t, http.StatusCreated, res.StatusCode, "%s", body)

	var parResponse struct {
		RequestURI string `json:"request_uri"`
		ExpiresIn  int64  `json:"expires_in"`
	}
	require.NoError(t, json.Unmarshal(body, &parResponse))
	assert.True(t, strings.HasPrefix(parResponse.RequestURI, "urn:ietf:params:oauth:request_uri:"))
	assert.Positive(t, parResponse.ExpiresIn)

	authURL, err := url.Parse(publicTS.URL + oauth2.AuthPath)
	require.NoError(t, err)
	authURL.RawQuery = url.Values{
		"client_id":   {conf.ClientID},
		"request_uri": {parResponse.RequestURI},
	}.Encode()
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err = noRedirect.Get(authURL.String())
	require.NoError(t, err)
	defer res.Body.Close() //nolint:errcheck
	require.Equal(t, http.StatusFound, res.StatusCode)
	location, err := res.Location()
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(location.String(), "https://login.example/"))
	assert.NotEmpty(t, location.Query().Get("login_challenge"))

	res, err = noRedirect.Get(authURL.String())
	require.NoError(t, err)
	defer res.Body.Close() //nolint:errcheck
	require.Equal(t, http.StatusFound, res.StatusCode)
	reusedLocation, err := res.Location()
	require.NoError(t, err)
	assert.False(t, strings.HasPrefix(reusedLocation.String(), "https://login.example/"))
	assert.Contains(t, reusedLocation.Query().Get("error"), "invalid_request_uri")
}

func TestCIBAFlow(t *testing.T) {
	ctx := t.Context()
	reg := testhelpers.NewRegistryMemory(t)
	publicTS, adminTS := testhelpers.NewOAuth2Server(ctx, t, reg)
	c, conf := newOAuth2Client(t, reg, "https://client.example/callback", func(c *client.Client) {
		c.GrantTypes = append(c.GrantTypes, string(fosite.GrantTypeCIBA))
		c.Scope = "openid offline"
	})
	testhelpers.NewLoginConsentUI(t, reg.Config(),
		testhelpers.HTTPServerNoExpectedCallHandler(t),
		testhelpers.HTTPServerNoExpectedCallHandler(t),
	)

	form := url.Values{
		"scope":      {"openid offline"},
		"login_hint": {"ciba-user"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, publicTS.URL+oauth2.CIBAAuthPath, strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(conf.ClientID, conf.ClientSecret)
	res, err := publicTS.Client().Do(req)
	require.NoError(t, err)
	defer res.Body.Close() //nolint:errcheck
	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	require.Equalf(t, http.StatusOK, res.StatusCode, "%s", body)

	var authResponse struct {
		AuthReqID      string `json:"auth_req_id"`
		ExpiresIn      int64  `json:"expires_in"`
		Interval       int    `json:"interval"`
		LoginChallenge string `json:"login_challenge"`
	}
	require.NoError(t, json.Unmarshal(body, &authResponse))
	require.NotEmpty(t, authResponse.AuthReqID)
	require.NotEmpty(t, authResponse.LoginChallenge)
	assert.Positive(t, authResponse.ExpiresIn)
	assert.Positive(t, authResponse.Interval)

	poll := func() (int, map[string]any) {
		values := url.Values{
			"grant_type":  {string(fosite.GrantTypeCIBA)},
			"auth_req_id": {authResponse.AuthReqID},
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, publicTS.URL+oauth2.TokenPath, strings.NewReader(values.Encode()))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(conf.ClientID, conf.ClientSecret)
		res, err := publicTS.Client().Do(req)
		require.NoError(t, err)
		defer res.Body.Close() //nolint:errcheck
		body, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		var payload map[string]any
		require.NoError(t, json.Unmarshal(body, &payload))
		return res.StatusCode, payload
	}

	status, payload := poll()
	require.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "authorization_pending", payload["error"])

	adminClient := hydra.NewAPIClient(hydra.NewConfiguration())
	adminClient.GetConfig().Servers = hydra.ServerConfigurations{{URL: adminTS.URL}}

	login, _, err := adminClient.OAuth2API.GetOAuth2LoginRequest(ctx).
		LoginChallenge(authResponse.LoginChallenge).
		Execute()
	require.NoError(t, err)
	assert.Contains(t, login.GetRequestedScope(), "openid")
	require.NotNil(t, login.OidcContext)
	assert.Equal(t, "ciba-user", login.OidcContext.GetLoginHint())

	acceptedLogin, _, err := adminClient.OAuth2API.AcceptOAuth2LoginRequest(ctx).
		LoginChallenge(authResponse.LoginChallenge).
		AcceptOAuth2LoginRequest(hydra.AcceptOAuth2LoginRequest{Subject: "ciba-user"}).
		Execute()
	require.NoError(t, err)
	require.NotEmpty(t, acceptedLogin.RedirectTo)

	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err = noRedirect.Get(acceptedLogin.RedirectTo)
	require.NoError(t, err)
	defer res.Body.Close() //nolint:errcheck
	require.Equal(t, http.StatusFound, res.StatusCode)
	consentLocation, err := res.Location()
	require.NoError(t, err)
	consentChallenge := consentLocation.Query().Get("consent_challenge")
	require.NotEmpty(t, consentChallenge)

	consent, _, err := adminClient.OAuth2API.GetOAuth2ConsentRequest(ctx).
		ConsentChallenge(consentChallenge).
		Execute()
	require.NoError(t, err)
	require.Equal(t, "ciba-user", consent.GetSubject())

	acceptedConsent, _, err := adminClient.OAuth2API.AcceptOAuth2ConsentRequest(ctx).
		ConsentChallenge(consentChallenge).
		AcceptOAuth2ConsentRequest(hydra.AcceptOAuth2ConsentRequest{
			GrantScope:               []string{"openid", "offline"},
			GrantAccessTokenAudience: consent.RequestedAccessTokenAudience,
			Session: &hydra.AcceptOAuth2ConsentRequestSession{
				AccessToken: map[string]interface{}{"foo": "bar"},
				IdToken:     map[string]interface{}{"email": "ciba@example.com"},
			},
		}).
		Execute()
	require.NoError(t, err)
	require.NotEmpty(t, acceptedConsent.RedirectTo)

	res, err = publicTS.Client().Get(acceptedConsent.RedirectTo)
	require.NoError(t, err)
	defer res.Body.Close() //nolint:errcheck
	require.Equal(t, http.StatusOK, res.StatusCode)

	status, payload = poll()
	require.Equalf(t, http.StatusOK, status, "%v", payload)
	assert.NotEmpty(t, payload["access_token"])
	assert.NotEmpty(t, payload["id_token"])
	assert.NotEmpty(t, payload["refresh_token"])
	introspection := testhelpers.IntrospectToken(t, payload["access_token"].(string), adminTS)
	assert.Equal(t, "ciba-user", introspection.Get("sub").String())
	assert.Equal(t, "bar", introspection.Get("ext.foo").String())

	status, payload = poll()
	require.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_grant", payload["error"])

	assert.Equal(t, c.GetID(), conf.ClientID)
}
