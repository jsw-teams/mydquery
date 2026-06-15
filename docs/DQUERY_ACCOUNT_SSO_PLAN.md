# dquery local account and SSO binding plan

## Account boundary

dquery owns the primary account system.

- `dquery_users.id` is a UUID and is the canonical local user id.
- local sessions are issued by dquery and stored only as HttpOnly cookies.
- resolver/profile ids are UUIDs and are separate from user ids.
- external SSO providers never become the primary account namespace.

## Current local flow

1. `GET /api/v1/dquery/setup/status`
   - returns whether any local dquery user exists.
2. `POST /api/v1/dquery/setup/init`
   - allowed only when no local users exist.
   - creates the first local `system_admin`.
   - creates a default resolver profile with its own UUID.
   - creates a local session cookie.
3. `POST /api/v1/dquery/auth/login`
   - verifies `local_passwords`.
   - creates a dquery session cookie.
4. `GET /api/v1/dquery/auth/me`
   - reads only the dquery session cookie.
   - does not accept account-system bearer tokens.

## Future SSO model

SSO is an optional identity binding layer.

Suggested tables:

```text
sso_providers
- id UUID primary key
- slug unique
- name
- type oauth2_authorization_code
- enabled
- client_id
- client_secret_encrypted
- authorize_url
- token_url
- userinfo_url
- redirect_uri
- scopes_json
- auto_create_users boolean
- created_at
- updated_at

external_identities
- id UUID primary key
- user_id UUID references dquery_users(id)
- provider_id UUID references sso_providers(id)
- external_subject
- external_email
- external_display_name
- profile_json
- created_at
- updated_at
- unique(provider_id, external_subject)
```

SSO login sequence:

1. `GET /auth/sso/{provider}/start`
   - loads enabled provider.
   - creates state and PKCE verifier server-side.
   - redirects to provider authorize URL.
2. `GET /auth/sso/{provider}/callback`
   - accepts only `code` and `state`.
   - rejects `account_session`, `access_token`, and `refresh_token` in the browser callback.
   - exchanges code server-side.
   - fetches userinfo server-side.
   - resolves `(provider_id, external_subject)` in `external_identities`.
3. If identity exists:
   - create local dquery session for `external_identities.user_id`.
4. If identity does not exist:
   - if `auto_create_users` is enabled, create a local `member` user and bind the identity.
   - otherwise require a logged-in local `system_admin` to bind it.

## account-system v2 provider

account-system v2 is one optional SSO provider:

```yaml
sso_providers:
  account_system:
    enabled: false
    type: oauth2_authorization_code
    client_id: "[UUID]"
    client_secret: "[SERVER_ONLY_SECRET]"
    authorize_url: "https://account.js.gripe/authorize"
    token_url: "https://gateway.js.gripe/api/v1/myaccount/oauth/token"
    userinfo_url: "https://gateway.js.gripe/api/v1/myaccount/oauth/userinfo"
    redirect_uri: "https://dquery.js.gripe/auth/sso/account-system/callback"
```

Do not use:

- `account_session` callback parameters
- account-system bearer tokens as dquery console sessions
- localStorage/sessionStorage for dquery session tokens
- account-system user ids as resolver ids

## UI rules

- `/console/` checks setup first, then local session.
- uninitialized installs redirect to `/setup/`.
- initialized but unauthenticated users redirect to `/login/`.
- `/login/` is local login first.
- SSO buttons appear only after providers are configured and enabled.
