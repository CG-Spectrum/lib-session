# @cgsi/session

Per-app sessions for CGSI apps. The sign-in hub makes the session; each app
holds a 15-minute token the hub signed **for that app**, in a cookie only that
app's host receives, and renews it at the hub. An app can check a token and can
never make one.

## Modes (`SESSION_MODE`)

| Value | Behaviour |
|---|---|
| unset, `shared`, or a typo | Today: the hub's shared cookie decides. This package does nothing. |
| `both` | The app's own session when there is one; otherwise the shared cookie. People are moved across quietly on a page load. Nothing is refused that `shared` would allow. |
| `own` | The app's own session only. |

Undo at any point: set it back and redeploy.

## Use

```ts
// src/lib/session.ts
import { createHub, createSessionMiddleware, originGuardMode, sessionMode } from "@cgsi/session";

const mode = sessionMode(process.env.SESSION_MODE);
export const options = {
  app: "console",
  hubUrl: process.env.AUTH_HOST_URL!,
  issuer: process.env.SESSION_ISSUER,           // defaults to hubUrl
  mode,
  originGuard: originGuardMode(process.env.SESSION_ORIGIN_GUARD, mode),
  secure: process.env.NODE_ENV === "production",
  legacyCookieNames: ["__Secure-authjs.session-token"],
};
export const hub = createHub(options);
export const handleSession = createSessionMiddleware(options, hub);
```

```ts
// src/middleware.ts
const r = await handleSession(req, { legacySignedIn: !!req.auth });
if (r) return r;
// ...the app's existing shared-cookie behaviour
```

```ts
// server code
import { readAppSession } from "@cgsi/session/server";
const session = await readAppSession(hub, secure, await cookies(), await headers());
```

Add the package to `transpilePackages` in `next.config` (it ships source).

## What it handles

- `/session/callback`: finishes a sign-in (state check, code exchange, cookies).
- `/session/signout`: clears the app's cookies and signs out at the hub.
- Renewal in the last minute of a token, on any request, with no redirect.
  The same request already sees the new token.
- Hub unreachable (never: hub refuses): the last token is honoured for up to
  60 minutes.
- Origin guard: a signed-in request that changes something must come from the
  app's own host. `SESSION_ORIGIN_GUARD` = `off`, `report` or `enforce`
  (default: off while `shared`, enforce otherwise).

## Cookies

`__Host-cgsi.session`, `__Host-cgsi.session-handle` (and two short-lived
helpers). Host-only, HttpOnly, Secure, SameSite=Lax. Never a parent domain.
