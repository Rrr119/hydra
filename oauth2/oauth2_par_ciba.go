// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/pborman/uuid"

	"github.com/ory/hydra/v2/client"
	"github.com/ory/hydra/v2/consent"
	"github.com/ory/hydra/v2/flow"
	"github.com/ory/hydra/v2/fosite"
	"github.com/ory/hydra/v2/fosite/handler/ciba"
	"github.com/ory/hydra/v2/x"
	"github.com/ory/x/sqlxx"
	"github.com/ory/x/urlx"
)

// oAuth2PushedAuthorizationRequest implements RFC 9126.
func (h *Handler) oAuth2PushedAuthorizationRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	request, err := h.r.OAuth2Provider().NewPushedAuthorizeRequest(ctx, r)
	if err != nil {
		h.r.OAuth2Provider().WritePushedAuthorizeError(ctx, w, request, err)
		return
	}

	session := NewSessionWithCustomClaims(ctx, h.c, "")
	var response fosite.PushedAuthorizeResponder
	if err := h.r.Transaction(ctx, func(ctx context.Context) (err error) {
		response, err = h.r.OAuth2Provider().NewPushedAuthorizeResponse(ctx, request, session)
		return err
	}); err != nil {
		h.r.OAuth2Provider().WritePushedAuthorizeError(ctx, w, request, err)
		return
	}

	h.r.OAuth2Provider().WritePushedAuthorizeResponse(ctx, w, request, response)
}

type cibaAuthenticationResponse struct {
	AuthReqID       string `json:"auth_req_id"`
	ExpiresIn       int64  `json:"expires_in"`
	Interval        int    `json:"interval"`
	LoginChallenge  string `json:"login_challenge,omitempty"`
	VerificationURI string `json:"verification_uri,omitempty"`
}

// oAuth2CIBAAuthentication implements the CIBA backchannel authentication endpoint.
func (h *Handler) oAuth2CIBAAuthentication(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := r.ParseMultipartForm(1 << 20); err != nil && err != http.ErrNotMultipart {
		h.r.Writer().WriteError(w, r, fosite.ErrInvalidRequest.WithHint("Unable to parse the request body.").WithWrap(err))
		return
	}
	if r.Method != http.MethodPost {
		h.r.Writer().WriteError(w, r, fosite.ErrInvalidRequest.WithHintf("HTTP method is '%s', expected 'POST'.", r.Method))
		return
	}

	oauthClient, err := h.r.OAuth2Provider().AuthenticateClient(ctx, r, r.PostForm)
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	request := ciba.NewRequest()
	request.Client = oauthClient
	request.Form = r.PostForm
	request.RequestedAt = time.Now().UTC()
	request.SetRequestedScopes(fosite.RemoveEmpty(strings.Split(r.PostForm.Get("scope"), " ")))
	request.SetRequestedAudience(fosite.GetAudiences(r.PostForm))
	if !request.GetRequestedScopes().Has("openid") {
		h.r.Writer().WriteError(w, r, fosite.ErrInvalidScope.WithHint("CIBA requests must include the 'openid' scope."))
		return
	}

	if !oauthClient.GetGrantTypes().Has(string(fosite.GrantTypeCIBA)) {
		h.r.Writer().WriteError(w, r, fosite.ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client is not allowed to use the CIBA grant type."))
		return
	}
	for _, scope := range request.GetRequestedScopes() {
		if !h.r.OAuth2ProviderConfig().GetScopeStrategy(ctx)(oauthClient.GetScopes(), scope) {
			h.r.Writer().WriteError(w, r, fosite.ErrInvalidScope.WithHintf("The OAuth 2.0 Client is not allowed to request scope '%s'.", scope))
			return
		}
	}
	if err := h.r.OAuth2ProviderConfig().GetAudienceStrategy(ctx)(oauthClient.GetAudience(), request.GetRequestedAudience()); err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	request.LoginHint, err = h.cibaLoginHint(ctx, r)
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}
	request.BindingMessage = r.PostForm.Get("binding_message")
	request.UserCode = r.PostForm.Get("user_code")
	if expiry := r.PostForm.Get("requested_expiry"); expiry != "" {
		seconds, err := strconv.ParseInt(expiry, 10, 64)
		if err != nil || seconds <= 0 {
			h.r.Writer().WriteError(w, r, fosite.ErrInvalidRequest.WithHint("The 'requested_expiry' parameter must be a positive integer."))
			return
		}
		request.RequestedExpiry = time.Now().UTC().Add(time.Duration(seconds) * time.Second)
	}

	session := NewSessionWithCustomClaims(ctx, h.c, "")
	response, err := ciba.NewResponse(ctx, request, session, h.r.OAuth2Storage().CIBAStorage(), h.r.OAuth2ProviderConfig())
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	concreteClient, ok := oauthClient.(*client.Client)
	if !ok {
		h.r.Writer().WriteError(w, r, fosite.ErrServerError.WithHint("The client manager returned an unsupported client type."))
		return
	}
	safeClient := *concreteClient
	safeClient.Secret = ""

	challenge := strings.ReplaceAll(uuid.New(), "-", "")
	verificationURL := urlx.SetQuery(
		urlx.AppendPaths(h.c.IssuerURL(ctx), CIBAVerificationPath),
		url.Values{"ciba_request": {request.Signature}},
	)
	consentContext, err := json.Marshal(map[string]interface{}{
		"ciba": map[string]interface{}{
			"login_hint":      request.LoginHint,
			"binding_message": request.BindingMessage,
			"user_code":       request.UserCode,
		},
	})
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}
	fl := &flow.Flow{
		ID:                challenge,
		NID:               h.r.Networker().NetworkID(ctx),
		RequestedScope:    []string(request.GetRequestedScopes()),
		RequestedAudience: []string(request.GetRequestedAudience()),
		OpenIDConnectContext: &flow.OAuth2ConsentRequestOpenIDConnectContext{
			LoginHint: request.LoginHint,
			ACRValues: fosite.RemoveEmpty(strings.Split(r.PostForm.Get("acr_values"), " ")),
		},
		Client:        &safeClient,
		ClientID:      safeClient.ID,
		RequestURL:    verificationURL.String(),
		SessionID:     sqlxx.NullString(strings.ReplaceAll(uuid.New(), "-", "")),
		RequestedAt:   time.Now().UTC().Truncate(time.Second),
		Context:       sqlxx.JSONRawMessage(consentContext),
		State:         flow.FlowStateLoginUnused,
		CIBARequestID: request.Signature,
	}
	loginChallenge, err := fl.ToLoginChallenge(ctx, h.r)
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	response.Extra["login_challenge"] = loginChallenge
	response.Extra["verification_uri"] = urlx.SetQuery(
		h.c.LoginURL(ctx),
		url.Values{"login_challenge": {loginChallenge}},
	).String()

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(cibaAuthenticationResponse{
		AuthReqID:       response.AuthReqID,
		ExpiresIn:       response.ExpiresIn,
		Interval:        response.Interval,
		LoginChallenge:  loginChallenge,
		VerificationURI: response.Extra["verification_uri"].(string),
	})
}

func (h *Handler) cibaLoginHint(ctx context.Context, r *http.Request) (string, error) {
	var provided []string
	for _, parameter := range []string{"login_hint", "id_token_hint", "login_hint_token"} {
		if r.PostForm.Get(parameter) != "" {
			provided = append(provided, parameter)
		}
	}
	if len(provided) == 0 {
		return "", fosite.ErrInvalidRequest.WithHint("One of 'login_hint', 'id_token_hint', or 'login_hint_token' is required.")
	}
	if len(provided) > 1 {
		return "", fosite.ErrInvalidRequest.WithHint("Only one of 'login_hint', 'id_token_hint', or 'login_hint_token' may be provided.")
	}
	if hint := r.PostForm.Get("login_hint"); hint != "" {
		return hint, nil
	}

	parameter := provided[0]
	claims, err := h.r.OpenIDJWTSigner().Decode(ctx, r.PostForm.Get(parameter))
	if err != nil {
		return "", fosite.ErrInvalidRequest.WithHintf("Unable to decode the '%s' parameter.", parameter).WithWrap(err)
	}
	if sub, _ := claims.Claims["sub"].(string); sub != "" {
		return sub, nil
	}
	return "", fosite.ErrInvalidRequest.WithHintf("The '%s' parameter does not contain a subject.", parameter)
}

func (h *Handler) handleOAuth2CIBAVerification(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	fl, err := h.r.ConsentStrategy().HandleOAuth2CIBARequest(ctx, w, r)
	if errors.Is(err, consent.ErrUserRedirected) {
		return
	} else if err != nil {
		x.LogError(r, err, h.r.Logger())
		h.r.Writer().WriteError(w, r, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":             "ok",
		"consent_request_id": fl.ConsentRequestID.String(),
	})
}
