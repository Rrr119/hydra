// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package ciba

import (
	"context"
	"time"

	"github.com/pkg/errors"

	"github.com/ory/hydra/v2/fosite"
	"github.com/ory/hydra/v2/fosite/handler/oauth2"
	"github.com/ory/hydra/v2/fosite/handler/openid"
	"github.com/ory/x/errorsx"
)

var _ fosite.TokenEndpointHandler = (*TokenHandler)(nil)

type TokenHandler struct {
	Storage interface {
		fosite.Transactional
		StorageProvider
		oauth2.AccessTokenStorageProvider
		oauth2.RefreshTokenStorageProvider
		oauth2.TokenRevocationStorageProvider
	}
	Strategy interface {
		oauth2.AccessTokenStrategyProvider
		oauth2.RefreshTokenStrategyProvider
		openid.OpenIDConnectTokenStrategyProvider
	}
	Config              fosite.Configurator
	IDTokenHandleHelper *openid.IDTokenHandleHelper
}

func (h *TokenHandler) CanSkipClientAuth(context.Context, fosite.AccessRequester) bool {
	return false
}

func (h *TokenHandler) CanHandleTokenEndpointRequest(_ context.Context, requester fosite.AccessRequester) bool {
	return requester.GetGrantTypes().ExactOne(string(fosite.GrantTypeCIBA))
}

func (h *TokenHandler) HandleTokenEndpointRequest(ctx context.Context, requester fosite.AccessRequester) error {
	if !h.CanHandleTokenEndpointRequest(ctx, requester) {
		return errorsx.WithStack(fosite.ErrUnknownRequest)
	}
	if !requester.GetClient().GetGrantTypes().Has(string(fosite.GrantTypeCIBA)) {
		return errorsx.WithStack(fosite.ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client is not allowed to use the CIBA grant type."))
	}

	authReqID := requester.GetRequestForm().Get("auth_req_id")
	if authReqID == "" {
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithHint("Request parameter 'auth_req_id' is missing."))
	}

	signature := Signature(authReqID)
	request, err := h.Storage.CIBAStorage().GetCIBARequest(ctx, signature, requester.GetSession())
	if errors.Is(err, fosite.ErrNotFound) {
		return errorsx.WithStack(fosite.ErrInvalidGrant.WithHint("The provided auth_req_id is invalid or has expired."))
	} else if errors.Is(err, fosite.ErrDeviceExpiredToken) {
		return errorsx.WithStack(fosite.ErrDeviceExpiredToken)
	} else if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	if request.GetClient().GetID() != requester.GetClient().GetID() {
		return errorsx.WithStack(fosite.ErrInvalidGrant.WithHint("The auth_req_id was issued to a different OAuth 2.0 Client."))
	}

	switch request.State {
	case StatePending:
		return errorsx.WithStack(fosite.ErrAuthorizationPending)
	case StateDenied:
		return errorsx.WithStack(fosite.ErrAccessDenied)
	}
	if time.Now().UTC().After(request.RequestedExpiry) {
		_ = h.Storage.CIBAStorage().ConsumeCIBARequest(ctx, signature)
		return errorsx.WithStack(fosite.ErrDeviceExpiredToken)
	}

	requester.SetRequestedScopes(request.GetRequestedScopes())
	requester.SetRequestedAudience(request.GetRequestedAudience())
	for _, scope := range request.GetGrantedScopes() {
		requester.GrantScope(scope)
	}
	for _, audience := range request.GetGrantedAudience() {
		requester.GrantAudience(audience)
	}
	requester.SetSession(request.GetSession())
	requester.SetID(request.GetID())
	requester.GetRequestForm().Set("auth_req_id_signature", signature)

	atLifespan := fosite.GetEffectiveLifespan(requester.GetClient(), fosite.GrantTypeCIBA, fosite.AccessToken, h.Config.GetAccessTokenLifespan(ctx))
	requester.GetSession().SetExpiresAt(fosite.AccessToken, time.Now().UTC().Add(atLifespan).Round(time.Second))

	rtLifespan := fosite.GetEffectiveLifespan(requester.GetClient(), fosite.GrantTypeCIBA, fosite.RefreshToken, h.Config.GetRefreshTokenLifespan(ctx))
	if rtLifespan > -1 {
		requester.GetSession().SetExpiresAt(fosite.RefreshToken, time.Now().UTC().Add(rtLifespan).Round(time.Second))
	}

	return nil
}

func (h *TokenHandler) PopulateTokenEndpointResponse(ctx context.Context, requester fosite.AccessRequester, responder fosite.AccessResponder) error {
	if !h.CanHandleTokenEndpointRequest(ctx, requester) {
		return errorsx.WithStack(fosite.ErrUnknownRequest)
	}

	accessToken, accessSignature, err := h.Strategy.AccessTokenStrategy().GenerateAccessToken(ctx, requester)
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	var refreshToken, refreshSignature string
	if h.canIssueRefreshToken(ctx, requester) {
		refreshToken, refreshSignature, err = h.Strategy.RefreshTokenStrategy().GenerateRefreshToken(ctx, requester)
		if err != nil {
			return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
		}
	}

	signature := requester.GetRequestForm().Get("auth_req_id_signature")
	if signature == "" {
		return errorsx.WithStack(fosite.ErrServerError.WithHint("The CIBA request signature is missing."))
	}

	if err := h.Storage.Transaction(ctx, func(ctx context.Context) error {
		if err := h.Storage.CIBAStorage().ConsumeCIBARequest(ctx, signature); err != nil {
			if errors.Is(err, fosite.ErrNotFound) {
				return errorsx.WithStack(fosite.ErrInvalidGrant.WithHint("The auth_req_id has already been used."))
			}
			return err
		}
		if err := h.Storage.AccessTokenStorage().CreateAccessTokenSession(ctx, accessSignature, requester.Sanitize([]string{})); err != nil {
			return err
		}
		if refreshSignature != "" {
			if err := h.Storage.RefreshTokenStorage().CreateRefreshTokenSession(ctx, refreshSignature, accessSignature, requester.Sanitize([]string{})); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	atLifespan := fosite.GetEffectiveLifespan(requester.GetClient(), fosite.GrantTypeCIBA, fosite.AccessToken, h.Config.GetAccessTokenLifespan(ctx))
	responder.SetAccessToken(accessToken)
	responder.SetTokenType(fosite.BearerAccessToken)
	responder.SetExpiresIn(getExpiresIn(requester, fosite.AccessToken, atLifespan))
	responder.SetScopes(requester.GetGrantedScopes())
	if refreshToken != "" {
		responder.SetExtra("refresh_token", refreshToken)
	}

	if requester.GetGrantedScopes().Has("openid") {
		session, ok := requester.GetSession().(openid.Session)
		if !ok {
			return errorsx.WithStack(fosite.ErrServerError.WithDebug("Failed to generate id token because the session does not implement openid.Session."))
		}
		claims := session.IDTokenClaims()
		if claims.Subject == "" {
			return errorsx.WithStack(fosite.ErrServerError.WithDebug("Failed to generate id token because subject is an empty string."))
		}
		claims.AccessTokenHash = h.IDTokenHandleHelper.GetAccessTokenHash(ctx, requester, responder)
		idTokenLifespan := fosite.GetEffectiveLifespan(requester.GetClient(), fosite.GrantTypeCIBA, fosite.IDToken, h.Config.GetIDTokenLifespan(ctx))
		if err := h.IDTokenHandleHelper.IssueExplicitIDToken(ctx, idTokenLifespan, requester, responder); err != nil {
			return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
		}
	}

	return nil
}

func (h *TokenHandler) canIssueRefreshToken(ctx context.Context, requester fosite.Requester) bool {
	scopes := h.Config.GetRefreshTokenScopes(ctx)
	if len(scopes) > 0 && !requester.GetGrantedScopes().HasOneOf(scopes...) {
		return false
	}
	return requester.GetClient().GetGrantTypes().Has(string(fosite.GrantTypeRefreshToken))
}

func getExpiresIn(requester fosite.Requester, tokenType fosite.TokenType, fallback time.Duration) time.Duration {
	if expiry := requester.GetSession().GetExpiresAt(tokenType); !expiry.IsZero() {
		return time.Until(expiry)
	}
	return fallback
}
