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
  60 minutes. See **The grace period** below for exactly when, and its limit.
- A hub that cannot answer in time (a timeout, a network error, or a `503`
  saying it is busy) is left alone for a moment: renewals answer "unreachable"
  without calling for `Retry-After` seconds, between 1 and 5, default 1.
  Finishing a sign-in is never held off this way. A `/token` call waits 8
  seconds: the app's clock starts before the hub's handler does, and a hub
  given too little time can answer just after the app has given up, having
  already acted.
- Several requests arriving at once with the same renewal handle make one call
  to the hub and share its answer, for a few seconds. **Within one server
  process only.** Each instance keeps its own, in memory, so separate
  instances, and the same app after a restart, can still renew the same handle
  at the same moment. The hub has to tolerate that; nothing here prevents it,
  and nothing should be built as though it does.
- `own`: a sign-in that cannot be finished because the hub did not answer is
  started again once, to the page the person was going to. A refusal is never
  retried. A hub that stays down cannot loop the browser: the restart sets a
  short-lived host-only cookie (`cgsi.session-restarted`, HttpOnly, 10 minutes,
  the life of a pending sign-in), the browser carries it back to the callback,
  and a restart only happens when it is absent. It is cleared on success and on
  the page shown after the second failure.
- Origin guard: a signed-in request that changes something must come from the
  app's own host. `SESSION_ORIGIN_GUARD` = `off`, `report` or `enforce`
  (default: off while `shared`, enforce otherwise).

## The grace period

An expired token is honoured, for up to 60 minutes past its expiry, in one
case only: a renewal was attempted **in that same request** and ended as
"unreachable". The middleware marks that request for server code with a
header it strips from anything a browser sent. The hub refusing (401 or 403),
no handle to renew with, and no attempt at all are all outside it, and end the
session as before.

Its limit, worth knowing: while the hub is being left alone after a failure
(up to 5 seconds), renewals answer "unreachable" without asking. So for those
few seconds a person the hub would by then refuse is carried on the grace
path, unasked. The first call made after that pause gets the real answer and
ends the session at once. This is the existing grace design, which already
carries a person for up to an hour on a hub that cannot answer; the pause adds
seconds to a window measured in minutes.

## Cookies

`__Host-cgsi.session`, `__Host-cgsi.session-handle` (and three short-lived
helpers). Host-only, HttpOnly, Secure, SameSite=Lax. Never a parent domain.

## Changes

### 0.1.2

- A hub that cannot answer in time is left alone briefly: renewals answer
  "unreachable" without calling, for `Retry-After` seconds (1 to 5, default 1).
  Finishing a sign-in is not held off.
- A `/token` call now waits 8 seconds for an answer, not 4. The key-set fetch
  is unchanged.
- Requests arriving together with the same renewal handle make one call to the
  hub and share its answer for a few seconds, within one server process.
- `own`: a sign-in the hub could not answer restarts once, instead of ending on
  the "could not be completed" page. Refusals are unchanged.

### 0.1.1

- A session the hub has ended is never passed through.
