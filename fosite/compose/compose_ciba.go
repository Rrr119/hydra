// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"github.com/ory/hydra/v2/fosite"
	"github.com/ory/hydra/v2/fosite/handler/ciba"
	"github.com/ory/hydra/v2/fosite/handler/oauth2"
	"github.com/ory/hydra/v2/fosite/handler/openid"
)

// CIBAFactory creates the token endpoint handler for CIBA.
func CIBAFactory(config fosite.Configurator, storage fosite.Storage, strategy interface{}) interface{} {
	return &ciba.TokenHandler{
		Storage: storage.(interface {
			fosite.Transactional
			ciba.StorageProvider
			oauth2.AccessTokenStorageProvider
			oauth2.RefreshTokenStorageProvider
			oauth2.TokenRevocationStorageProvider
		}),
		Strategy: strategy.(interface {
			oauth2.AccessTokenStrategyProvider
			oauth2.RefreshTokenStrategyProvider
			openid.OpenIDConnectTokenStrategyProvider
		}),
		Config: config,
		IDTokenHandleHelper: &openid.IDTokenHandleHelper{
			IDTokenStrategy: strategy.(openid.OpenIDConnectTokenStrategyProvider),
		},
	}
}
