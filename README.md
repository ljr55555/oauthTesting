\# OAuth IDP Scope Test Scripts



This repo contains two small Flask test scripts for comparing claims returned by an OAuth IDP for different OIDC scope combinations.



\## Scripts



\- `getJWTInfo.py`

&#x20; - Requests multiple scope combinations

&#x20; - Decodes the JWT access token

&#x20; - Compares claims across runs



\- `getUserInfo.py`

&#x20; - Requests multiple scope combinations

&#x20; - Calls the OIDC UserInfo endpoint

&#x20; - Compares claims across runs



\## Purpose



Use these scripts to compare what is returned for:



\- `openid`

\- `openid profile`

\- `openid email`



The UserInfo script also supports:



\- `openid phone`

\- `openid address`



\## Config



Both scripts use `config.py`.



Example:



```python

OAUTH\_CLIENT\_ID = "REPLACE\_WITH\_CLIENT\_ID"

OAUTH\_CLIENT\_SECRET = "REPLACE\_WITH\_CLIENT\_SECRET"

OAUTH\_URL\_BASE = "https://your-idp.example.com"

OAUTH\_AUTHORIZE\_URL = "https://your-idp.example.com/as/authorization.oauth2"

OAUTH\_TOKEN\_URL = "https://your-idp.example.com/as/token.oauth2"

REDIRECT\_URI = "/oauth2/v1/authorize/callback"

REDIRECT\_URL = "https://localhost/oauth2/v1/authorize/callback"

TLS\_VERIFY = True

```



\## Run



```bash

python getJWTInfo.py

python getUserInfo.py

```



Then browse to:



```text

https://localhost

```



\## Output



Both scripts return JSON reports showing:



\- requested scopes

\- returned claims

\- differences between scope combinations



\## Notes



\- The JWT script inspects claims in the access token.

\- The UserInfo script inspects claims returned by the UserInfo endpoint.

\- If the goal is to identify which attributes are associated with each scope, use the UserInfo script.



