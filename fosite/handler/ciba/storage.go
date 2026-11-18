// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package ciba

import (
	"context"
	"time"

	"github.com/ory/hydra/v2/fosite"
)

// Approval contains the result of a successful end-user consent flow.
type Approval struct {
	ClientID         string
	Subject          string
	GrantedScopes    []string
	GrantedAudience  []string
	AuthTime         time.Time
	RequestedAt      time.Time
	ACR              string
	AMR              []string
	IDTokenClaims    map[string]interface{}
	AccessTokenExtra map[string]interface{}
}

// Storage persists CIBA authentication requests.
type Storage interface {
	CreateCIBARequest(ctx context.Context, signature string, request *Request) error
	GetCIBARequest(ctx context.Context, signature string, session fosite.Session) (*Request, error)
	ApproveCIBARequest(ctx context.Context, signature string, approval Approval) error
	DenyCIBARequest(ctx context.Context, signature string) error
	ConsumeCIBARequest(ctx context.Context, signature string) error
}

type StorageProvider interface {
	CIBAStorage() Storage
}
