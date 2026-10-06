# Sense/Net Authentication server

SN-Auth is a lightweight authentication server implementation for Sense/Net repositories.

The authentication server consists of two parts:
- An API through which the client can log in/register etc. (recommended for custom UI)
- A built-in UI that you do not need to implement in your application.

The description of the API endpoints can be found in the swagger documentation.

## Concurrent browser sessions

By default, the same user can sign in from multiple browsers or devices using the
same application URL. Each completed login creates an independent session.
Refreshing or logging out of one session does not revoke another session.

To require a single active session per user and application, configure the
authentication server with this environment variable:

```text
JwtSettings__SingleSessionPerUser=true
```

The equivalent JSON setting is `JwtSettings.SingleSessionPerUser`. Its default is
`false`; omit the environment variable or set it to `false` to allow concurrent
sessions. Restart the authentication server after changing the configuration.
The single-session scope remains **user ID + application SiteUrl**, not a global
limit across all applications. In the redirect login flow, SiteUrl is the client
application's RedirectUrl (for example, `https://adminui.test.sensenet.com`).

Access/refresh response fields and endpoints are unchanged. Refresh tokens and
callback auth codes are single-use; successful MFA also consumes its challenge.
Earlier access tokens from the same session remain valid until their original
expiry or session logout, so logout racing with refresh still revokes that session.
New logins in single-session mode revoke the previous session's access and refresh
tokens. Consumers must save the replacement refresh token after every refresh.

Token state remains in memory in one SNAuth process, and expired tokens are removed
when new tokens are issued. Restarting loses all sessions; this change does not add
shared persistence for replicas. Revocation is enforced by SNAuth's validation and
refresh endpoints. A repository that validates JWT signatures locally can continue
to accept an issued access token until its expiry unless it also checks revocation.

Run the authentication regression tests with:

```text
dotnet test src/SenseNetAuth.sln
```
