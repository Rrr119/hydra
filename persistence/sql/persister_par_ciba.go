// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package sql

import (
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/ory/hydra/v2/fosite"
	"github.com/ory/hydra/v2/fosite/handler/ciba"
	"github.com/ory/hydra/v2/fosite/handler/openid"
	"github.com/ory/hydra/v2/oauth2"
	"github.com/ory/pop/v6"
	"github.com/ory/x/otelx"
)

const (
	parResponseTypesKey       = "__ory_par_response_types"
	parRedirectURIKey         = "__ory_par_redirect_uri"
	parStateKey               = "__ory_par_state"
	parResponseModeKey        = "__ory_par_response_mode"
	parDefaultResponseModeKey = "__ory_par_default_response_mode"
)

var (
	_ fosite.PARStorageProvider = (*Persister)(nil)
	_ ciba.StorageProvider      = (*Persister)(nil)
)

func (p *Persister) PARStorage() fosite.PARStorage {
	return p
}

func (p *Persister) CIBAStorage() ciba.Storage {
	return p
}

func cloneURLValues(values url.Values) url.Values {
	result := make(url.Values, len(values))
	for key, value := range values {
		result[key] = append([]string(nil), value...)
	}
	return result
}

func parExpiry(request fosite.AuthorizeRequester) time.Time {
	session := request.GetSession()
	if session == nil {
		return time.Now().UTC().Add(90 * time.Second)
	}
	for _, tokenType := range []fosite.TokenType{fosite.PushedAuthorizeRequestContext, fosite.AuthorizeCode} {
		if expiry := session.GetExpiresAt(tokenType); !expiry.IsZero() {
			return expiry
		}
	}
	return time.Now().UTC().Add(90 * time.Second)
}

func (p *Persister) CreatePARSession(ctx context.Context, requestURI string, request fosite.AuthorizeRequester) (err error) {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.sql.CreatePARSession")
	defer otelx.End(span, &err)

	expiry := parExpiry(request)
	if session := request.GetSession(); session != nil {
		session.SetExpiresAt(fosite.PushedAuthorizeRequestContext, expiry)
		session.SetExpiresAt(fosite.AuthorizeCode, expiry)
	}

	form := cloneURLValues(request.GetRequestForm())
	form.Set(parResponseTypesKey, strings.Join(request.GetResponseTypes(), " "))
	if redirectURI := request.GetRedirectURI(); redirectURI != nil {
		form.Set(parRedirectURIKey, redirectURI.String())
	}
	form.Set(parStateKey, request.GetState())
	form.Set(parResponseModeKey, string(request.GetResponseMode()))
	form.Set(parDefaultResponseModeKey, string(request.GetDefaultResponseMode()))

	stored := &fosite.Request{
		ID:                request.GetID(),
		RequestedAt:       request.GetRequestedAt(),
		Client:            request.GetClient(),
		RequestedScope:    request.GetRequestedScopes(),
		GrantedScope:      request.GetGrantedScopes(),
		RequestedAudience: request.GetRequestedAudience(),
		GrantedAudience:   request.GetGrantedAudience(),
		Form:              form,
		Session:           request.GetSession(),
	}
	return p.createSession(ctx, requestURI, stored, sqlTableOpenID, expiry)
}

func (p *Persister) GetPARSession(ctx context.Context, requestURI string) (_ fosite.AuthorizeRequester, err error) {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.sql.GetPARSession")
	defer otelx.End(span, &err)

	session := openid.NewDefaultSession()
	stored, err := p.findSessionBySignature(ctx, requestURI, session, sqlTableOpenID)
	if err != nil {
		return nil, err
	}

	expiry := session.GetExpiresAt(fosite.PushedAuthorizeRequestContext)
	if expiry.IsZero() {
		expiry = session.GetExpiresAt(fosite.AuthorizeCode)
	}
	if !expiry.IsZero() && time.Now().UTC().After(expiry) {
		_ = p.deleteSessionBySignature(ctx, requestURI, sqlTableOpenID)
		return nil, errors.WithStack(fosite.ErrNotFound)
	}

	request, ok := stored.(*fosite.Request)
	if !ok {
		return nil, errors.Errorf("expected *fosite.Request, got %T", stored)
	}

	form := request.GetRequestForm()
	authorize := fosite.NewAuthorizeRequest()
	authorize.Request = *request
	authorize.ResponseTypes = fosite.Arguments(strings.Fields(form.Get(parResponseTypesKey)))
	authorize.State = form.Get(parStateKey)
	authorize.ResponseMode = fosite.ResponseModeType(form.Get(parResponseModeKey))
	authorize.DefaultResponseMode = fosite.ResponseModeType(form.Get(parDefaultResponseModeKey))
	if rawRedirectURI := form.Get(parRedirectURIKey); rawRedirectURI != "" {
		authorize.RedirectURI, err = url.Parse(rawRedirectURI)
		if err != nil {
			return nil, errors.WithStack(err)
		}
	}
	return authorize, nil
}

func (p *Persister) DeletePARSession(ctx context.Context, requestURI string) (err error) {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.sql.DeletePARSession")
	defer otelx.End(span, &err)
	return p.deleteSessionBySignature(ctx, requestURI, sqlTableOpenID)
}

func cibaStoredRequest(request *ciba.Request) *fosite.Request {
	return &fosite.Request{
		ID:                request.GetID(),
		RequestedAt:       request.GetRequestedAt(),
		Client:            request.GetClient(),
		RequestedScope:    request.GetRequestedScopes(),
		GrantedScope:      request.GetGrantedScopes(),
		RequestedAudience: request.GetRequestedAudience(),
		GrantedAudience:   request.GetGrantedAudience(),
		Form:              ciba.EncodeMetadata(request),
		Session:           request.GetSession(),
	}
}

func (p *Persister) CreateCIBARequest(ctx context.Context, signature string, request *ciba.Request) (err error) {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.sql.CreateCIBARequest")
	defer otelx.End(span, &err)

	if request.RequestedExpiry.IsZero() {
		request.RequestedExpiry = time.Now().UTC().Add(10 * time.Minute)
	}
	request.GetSession().SetExpiresAt(fosite.CIBARequestContext, request.RequestedExpiry)
	request.GetSession().SetExpiresAt(fosite.AuthorizeCode, request.RequestedExpiry)
	return p.createSession(ctx, ciba.PendingKey(signature), cibaStoredRequest(request), sqlTableOpenID, request.RequestedExpiry)
}

func (p *Persister) GetCIBARequest(ctx context.Context, signature string, session fosite.Session) (_ *ciba.Request, err error) {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.sql.GetCIBARequest")
	defer otelx.End(span, &err)

	type candidate struct {
		key   string
		state ciba.State
	}
	for _, candidate := range []candidate{
		{key: ciba.ApprovedKey(signature), state: ciba.StateApproved},
		{key: ciba.PendingKey(signature), state: ciba.StatePending},
		{key: ciba.DeniedKey(signature), state: ciba.StateDenied},
	} {
		stored, err := p.findSessionBySignature(ctx, candidate.key, session, sqlTableOpenID)
		if errors.Is(err, fosite.ErrNotFound) || errors.Is(err, fosite.ErrInactiveToken) {
			continue
		} else if err != nil {
			return nil, err
		}

		request, ok := stored.(*fosite.Request)
		if !ok {
			return nil, errors.Errorf("expected *fosite.Request, got %T", stored)
		}
		result := &ciba.Request{Request: *request, State: candidate.state, Signature: signature}
		ciba.DecodeMetadata(result)
		if result.RequestedExpiry.IsZero() {
			result.RequestedExpiry = request.GetSession().GetExpiresAt(fosite.CIBARequestContext)
		}
		if !result.RequestedExpiry.IsZero() && time.Now().UTC().After(result.RequestedExpiry) {
			_ = p.deleteSessionBySignature(ctx, candidate.key, sqlTableOpenID)
			return nil, errors.WithStack(fosite.ErrDeviceExpiredToken)
		}
		return result, nil
	}

	return nil, errors.WithStack(fosite.ErrNotFound)
}

func (p *Persister) ApproveCIBARequest(ctx context.Context, signature string, approval ciba.Approval) (err error) {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.sql.ApproveCIBARequest")
	defer otelx.End(span, &err)

	request, err := p.GetCIBARequest(ctx, signature, oauth2.NewSessionWithCustomClaims(ctx, p.r.Config(), approval.Subject))
	if err != nil {
		return err
	}
	if request.State != ciba.StatePending {
		return errors.WithStack(fosite.ErrNotFound)
	}

	session := oauth2.NewSessionWithCustomClaims(ctx, p.r.Config(), approval.Subject)
	session.ClientID = approval.ClientID
	session.DefaultSession.Claims.Subject = approval.Subject
	session.DefaultSession.Claims.AuthTime = approval.AuthTime
	session.DefaultSession.Claims.RequestedAt = approval.RequestedAt
	session.DefaultSession.Claims.AuthenticationContextClassReference = approval.ACR
	session.DefaultSession.Claims.AuthenticationMethodsReferences = approval.AMR
	session.DefaultSession.Claims.Extra = cloneClaims(approval.IDTokenClaims)
	session.Extra = cloneClaims(approval.AccessTokenExtra)
	session.SetExpiresAt(fosite.CIBARequestContext, request.RequestedExpiry)
	session.SetExpiresAt(fosite.AuthorizeCode, request.RequestedExpiry)

	request.State = ciba.StateApproved
	request.GrantedScope = approval.GrantedScopes
	request.GrantedAudience = approval.GrantedAudience
	request.SetSession(session)

	return p.Transaction(ctx, func(ctx context.Context, _ *pop.Connection) error {
		if err := p.deleteSessionBySignature(ctx, ciba.PendingKey(signature), sqlTableOpenID); err != nil && !errors.Is(err, fosite.ErrNotFound) {
			return err
		}
		return p.createSession(ctx, ciba.ApprovedKey(signature), cibaStoredRequest(request), sqlTableOpenID, request.RequestedExpiry)
	})
}

func (p *Persister) DenyCIBARequest(ctx context.Context, signature string) (err error) {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.sql.DenyCIBARequest")
	defer otelx.End(span, &err)

	request, err := p.GetCIBARequest(ctx, signature, oauth2.NewSessionWithCustomClaims(ctx, p.r.Config(), ""))
	if err != nil {
		return err
	}
	if request.State != ciba.StatePending {
		return errors.WithStack(fosite.ErrNotFound)
	}
	request.State = ciba.StateDenied

	return p.Transaction(ctx, func(ctx context.Context, _ *pop.Connection) error {
		if err := p.deleteSessionBySignature(ctx, ciba.PendingKey(signature), sqlTableOpenID); err != nil && !errors.Is(err, fosite.ErrNotFound) {
			return err
		}
		return p.createSession(ctx, ciba.DeniedKey(signature), cibaStoredRequest(request), sqlTableOpenID, request.RequestedExpiry)
	})
}

func (p *Persister) ConsumeCIBARequest(ctx context.Context, signature string) (err error) {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.sql.ConsumeCIBARequest")
	defer otelx.End(span, &err)
	return p.deleteSessionBySignature(ctx, ciba.ApprovedKey(signature), sqlTableOpenID)
}

func cloneClaims(claims map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{}, len(claims))
	for key, value := range claims {
		result[key] = value
	}
	return result
}
