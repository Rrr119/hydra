// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package ciba

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/ory/hydra/v2/fosite"
	"github.com/ory/hydra/v2/fosite/token/hmac"
	"github.com/ory/x/errorsx"
)

const (
	AuthReqIDPrefix = "ory_ciba_"
	pendingPrefix   = "ciba-pending:"
	approvedPrefix  = "ciba-approved:"
	deniedPrefix    = "ciba-denied:"
)

// State is the lifecycle state of a CIBA authentication request.
type State int16

const (
	StatePending State = iota
	StateApproved
	StateDenied
)

// Request is a CIBA authentication request.
type Request struct {
	fosite.Request

	State           State
	LoginHint       string
	BindingMessage  string
	UserCode        string
	RequestedExpiry time.Time
	Interval        int
	Signature       string
}

func NewRequest() *Request {
	return &Request{Request: *fosite.NewRequest()}
}

func (r *Request) Sanitize(allowedParameters []string) fosite.Requester {
	sanitized := r.Request.Sanitize(allowedParameters)
	request, _ := sanitized.(*fosite.Request)
	return &Request{
		Request:         *request,
		State:           r.State,
		LoginHint:       r.LoginHint,
		BindingMessage:  r.BindingMessage,
		UserCode:        r.UserCode,
		RequestedExpiry: r.RequestedExpiry,
		Interval:        r.Interval,
		Signature:       r.Signature,
	}
}

// Signature returns the storage signature for an auth_req_id.
func Signature(authReqID string) string {
	sum := sha256.Sum256([]byte(authReqID))
	return hex.EncodeToString(sum[:])
}

// NewAuthReqID creates a new high-entropy auth_req_id.
func NewAuthReqID() (string, error) {
	key, err := hmac.RandomBytes(32)
	if err != nil {
		return "", errorsx.WithStack(err)
	}
	return AuthReqIDPrefix + base64.RawURLEncoding.EncodeToString(key), nil
}

// Response is returned by the CIBA backchannel authentication endpoint.
type Response struct {
	AuthReqID string
	ExpiresIn int64
	Interval  int
	Extra     map[string]interface{}
}

// NewResponse creates and persists a CIBA authentication request.
func NewResponse(ctx context.Context, request *Request, session fosite.Session, storage Storage, config fosite.Configurator) (*Response, error) {
	authReqID, err := NewAuthReqID()
	if err != nil {
		return nil, errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	request.Signature = Signature(authReqID)
	request.ID = request.GetID()
	request.RequestedAt = time.Now().UTC()
	request.State = StatePending

	lifespanConfig, ok := config.(fosite.CIBARequestLifespanProvider)
	if !ok {
		return nil, errorsx.WithStack(fosite.ErrServerError.WithHint("CIBA request lifespan is not configured."))
	}
	intervalConfig, ok := config.(fosite.CIBAIntervalProvider)
	if !ok {
		return nil, errorsx.WithStack(fosite.ErrServerError.WithHint("CIBA polling interval is not configured."))
	}

	now := time.Now().UTC()
	expiresAt := now.Add(lifespanConfig.GetCIBARequestLifespan(ctx))
	if request.RequestedExpiry.After(now) && request.RequestedExpiry.Before(expiresAt) {
		expiresAt = request.RequestedExpiry
	}
	request.RequestedExpiry = expiresAt
	request.Interval = int(intervalConfig.GetCIBAInterval(ctx).Seconds())
	if request.Interval < 1 {
		request.Interval = 1
	}

	session.SetExpiresAt(fosite.CIBARequestContext, expiresAt)
	session.SetExpiresAt(fosite.AuthorizeCode, expiresAt)
	request.SetSession(session)

	if err := storage.CreateCIBARequest(ctx, request.Signature, request); err != nil {
		return nil, errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	return &Response{
		AuthReqID: authReqID,
		ExpiresIn: int64(time.Until(expiresAt).Seconds()),
		Interval:  request.Interval,
		Extra:     map[string]interface{}{},
	}, nil
}

const (
	FormLoginHint       = "__ory_ciba_login_hint"
	FormBindingMessage  = "__ory_ciba_binding_message"
	FormUserCode        = "__ory_ciba_user_code"
	FormRequestedExpiry = "__ory_ciba_requested_expiry"
	FormInterval        = "__ory_ciba_interval"
	FormState           = "__ory_ciba_state"
)

func PendingKey(signature string) string {
	return formKey("pending", signature)
}

func ApprovedKey(signature string) string {
	return formKey("approved", signature)
}

func DeniedKey(signature string) string {
	return formKey("denied", signature)
}

func formKey(kind, signature string) string {
	switch kind {
	case "pending":
		return fmt.Sprintf("%s%s", pendingPrefix, signature)
	case "approved":
		return fmt.Sprintf("%s%s", approvedPrefix, signature)
	case "denied":
		return fmt.Sprintf("%s%s", deniedPrefix, signature)
	default:
		panic("unknown CIBA form key kind")
	}
}

// EncodeMetadata returns a copy of the request form with CIBA metadata added.
func EncodeMetadata(request *Request) url.Values {
	form := make(url.Values, len(request.GetRequestForm())+6)
	for key, values := range request.GetRequestForm() {
		form[key] = append([]string(nil), values...)
	}
	form.Set(FormLoginHint, request.LoginHint)
	form.Set(FormBindingMessage, request.BindingMessage)
	form.Set(FormUserCode, request.UserCode)
	form.Set(FormRequestedExpiry, request.RequestedExpiry.UTC().Format(time.RFC3339Nano))
	form.Set(FormInterval, strconv.Itoa(request.Interval))
	form.Set(FormState, strconv.Itoa(int(request.State)))
	return form
}

// DecodeMetadata hydrates CIBA-specific values from the request form.
func DecodeMetadata(request *Request) {
	form := request.GetRequestForm()
	request.LoginHint = form.Get(FormLoginHint)
	request.BindingMessage = form.Get(FormBindingMessage)
	request.UserCode = form.Get(FormUserCode)
	request.Interval, _ = strconv.Atoi(form.Get(FormInterval))
	if state, err := strconv.Atoi(form.Get(FormState)); err == nil {
		request.State = State(state)
	}
	if expiry, err := time.Parse(time.RFC3339Nano, form.Get(FormRequestedExpiry)); err == nil {
		request.RequestedExpiry = expiry
	}
}
