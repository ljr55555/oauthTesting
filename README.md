# OAuth IDP Scope Test Scripts

This repo contains two small Flask test scripts for comparing claims returned by an OAuth IDP for different OIDC scope combinations.

## Scripts

- `getJWTInfo.py`
  - Requests multiple scope combinations
  - Decodes the JWT access token
  - Compares claims across runs

- `getUserInfo.py`
  - Requests multiple scope combinations
  - Calls the OIDC UserInfo endpoint
  - Compares claims across runs

## Purpose

Use these scripts to compare what is returned for:

- `openid`
- `openid profile`
- `openid email`

The UserInfo script also supports:

- `openid phone`
- `openid address`

## Config

Both scripts use `config.py`.

Example:

```python
OAUTH_CLIENT_ID = "REPLACE_WITH_CLIENT_ID"
OAUTH_CLIENT_SECRET = "REPLACE_WITH_CLIENT_SECRET"
OAUTH_URL_BASE = "https://your-idp.example.com"
OAUTH_AUTHORIZE_URL = "https://your-idp.example.com/as/authorization.oauth2"
OAUTH_TOKEN_URL = "https://your-idp.example.com/as/token.oauth2"
REDIRECT_URI = "/oauth2/v1/authorize/callback"
REDIRECT_URL = "https://localhost/oauth2/v1/authorize/callback"
TLS_VERIFY = True
```

## Run

```bash
python getJWTInfo.py
python getUserInfo.py
```

Then browse to:

```text
https://localhost
```

## Output

Both scripts return JSON reports showing:

- requested scopes
- returned claims
- differences between scope combinations

## Notes

- The JWT script inspects claims in the access token.
- The UserInfo script inspects claims returned by the UserInfo endpoint.
- If the goal is to identify which attributes are associated with each scope, use the UserInfo script.
