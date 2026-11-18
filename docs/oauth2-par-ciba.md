# Pushed Authorization Requests and CIBA

Hydra supports OAuth 2.0 Pushed Authorization Requests (PAR, RFC 9126) and
OpenID Connect Client-Initiated Backchannel Authentication (CIBA, polling
mode).

## Pushed Authorization Requests

Clients authenticate at the PAR endpoint exactly as they do at the token
endpoint. The authorization parameters are sent in a form-encoded request:

```bash
curl -u mobile-client:secret \
  -d response_type=code \
  -d client_id=mobile-client \
  -d redirect_uri=https://mobile.example/callback \
  -d scope="openid offline" \
  -d state=af0ifjsldkj \
  https://hydra.example/oauth2/par
```

The endpoint responds with `201 Created`:

```json
{
  "request_uri": "urn:ietf:params:oauth:request_uri:...",
  "expires_in": 90
}
```

The browser flow then uses only `client_id` and `request_uri` at the
authorization endpoint:

```text
https://hydra.example/oauth2/auth?client_id=mobile-client&request_uri=urn:ietf:params:oauth:request_uri:...
```

The `request_uri` is single-use. Hydra removes it as soon as the authorization
request is retrieved, and rejects expired or unknown request URIs with
`invalid_request_uri`. OIDC request objects continue to use their pre-registered
`request_uris`; PAR request URIs are always issued and validated by Hydra.
The endpoint is also available as `/oauth2/pushed-authorization-request`.

## CIBA

Clients must be allowed to use the grant type
`urn:openid:params:grant-type:ciba`. Start a request at the backchannel
authentication endpoint:

```bash
curl -u internal-service:secret \
  -d scope="openid offline" \
  -d login_hint=user@example.com \
  -d binding_message="Approve login on your phone" \
  https://hydra.example/oauth2/backchannel/authentication
```

The response contains the standard polling fields:

```json
{
  "auth_req_id": "ory_ciba_...",
  "expires_in": 600,
  "interval": 5,
  "login_challenge": "...",
  "verification_uri": "https://login.example/?login_challenge=..."
}
```

`login_challenge` and `verification_uri` are Hydra extensions that connect CIBA
to the existing login and consent flow. An authentication device can use the
existing `/admin/oauth2/auth/requests/login` and
`/admin/oauth2/auth/requests/consent` APIs to approve the request. Hydra
continues the flow through `/oauth2/ciba/verify`, which redirects to the
configured consent app. Accepting consent makes the CIBA request available at
the token endpoint.

Poll the token endpoint with the client's normal token authentication:

```bash
curl -u internal-service:secret \
  -d grant_type=urn:openid:params:grant-type:ciba \
  -d auth_req_id=ory_ciba_... \
  https://hydra.example/oauth2/token
```

While the user has not yet approved, Hydra returns `400` with
`authorization_pending`. A denied request returns `access_denied`, and an
expired request returns `expired_token`. A successful exchange behaves like the
authorization code grant: access, refresh, and (when `openid` was granted) ID
tokens are issued, and the `auth_req_id` is consumed.

The following aliases are accepted for the backchannel endpoint:

- `/oauth2/backchannel/authenticate`
- `/oauth2/ciba/auth`

Discovery advertises the canonical endpoint as
`backchannel_authentication_endpoint` and `poll` as the supported token delivery
mode.
