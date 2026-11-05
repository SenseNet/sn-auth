# External login: state and S256 binding

Deploy this server before deploying the companion AdminUI changes in
`SenseNet/sn-client` branch `codex/auth-lifecycle-fixes`. Existing clients remain
compatible when they omit all binding fields. The new client requires a bound
callback and reports an authentication error against an older server.

The browser creates a fresh cryptographic `state` and RFC 7636 verifier for each
login, storing them in sessionStorage for that tab, repository, auth server and
callback. The `/Login` request adds `state`, `codeChallenge` (base64url SHA-256 of
the verifier) and `codeChallengeMethod=S256` to `RedirectUrl` and `CallbackUri`.
Partial or malformed binding is rejected. The callback must share the allowed
RedirectUrl's scheme, host and port.

Password, remembered login and MFA keep the original binding. Registration and
password recovery preserve the encoded login context. The successful callback
contains `auth_code` and `state`. The client validates and consumes its matching
pending transaction before posting `{ token, codeVerifier }` to
`/api/auth/convert-auth-token`.

The server verifies proof before atomically consuming a code. Missing/wrong proof
cannot redeem or burn a bound code. A proof-bearing request cannot redeem a
legacy unbound code. Bound MFA tokens cannot bypass proof through the direct
MFA login API. Session responses retain their existing accessToken/refreshToken
fields, and session rotation, parallel sessions and SingleSessionPerUser keep
their existing scope.

`AuthTokenExpiryMinutes` and `MultiFactorAuthExpiryMinutes` now expire in minutes.
Previously those two settings were inadvertently interpreted as days. Review
their configured values before rollout. Temporary codes and sessions still live
in one server process's memory.

Validation:

```powershell
dotnet test src/SenseNetAuth.sln --no-restore
dotnet publish src/sn-auth/SenseNetAuth.csproj -c Release --no-restore
```

Regression coverage includes real HTTP forms/callbacks/navigation, proof and
single-use races, MFA, legacy compatibility, minute expiry, and the existing
single/parallel-session cases. Complete the companion AdminUI's
`apps/sensenet/AUTHENTICATION-TESTING.md` matrix against the intended test servers
before promoting both changes.
