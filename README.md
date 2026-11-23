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
import { readAppSession, readLauncherApps } from "@cgsi/session/server";
const session = await readAppSession(hub, secure, await cookies(), await headers());
const launcherApps = readLauncherApps(secure, await cookies()); // tiles only, see below
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

## The launcher's list of apps

The hub sends the person's app keys beside the token at every grant and
renewal. This package stores them in `__Host-cgsi.session-apps` and hands them
back through `readLauncherApps(secure, cookies)`, so a launcher can draw tiles
without the app knowing anything else about what the person can open.

**⛔ It is a display list. It decides nothing.** It is not a claim in the
token, so nothing about it is signed; it sits in a cookie, and a person who
opens their own browser's storage can put whatever they like in it. The most a
changed value can do is show somebody a tile that refuses them when they click
it, which is what a revoked grant does today anyway. If the question is "may
this person do X", the answer is the token's claims or the app's own gate,
never this. It is named `launcherApps` everywhere for that reason.

It is read and written through one rule: an array of app keys
(`^[a-z][a-z0-9-]{1,40}$`), at most 40 of them, at most 1024 bytes stored.
Today's whole estate is 24 keys and 262 bytes, against roughly 4096 a browser
will carry. Anything else is treated as **absent** and never throws.

`null` (absent) and `[]` (empty) are different answers and must stay that way:

| What came back | Means | What an app should do |
|---|---|---|
| `null` | the hub sent no list: an older hub, a person it does not apply to, or nothing usable in the cookie | fall back to its current source |
| `[]` | the hub sent a list and it is empty | show no tiles |

A renewal carries the list on the same request that renewed, exactly as the
new token does, so server code sees it at once. A grant that carries no list
clears the cookie rather than leaving the last one behind, and it is cleared
wherever the other cookies are: sign-out, a session the hub has ended, and any
refusal.

## Permissions from the access model

Two helpers, for two different jobs. ⛔ Never swap them.

```ts
import { createPermissionCheck, personFromSession, showsPermission } from "@cgsi/session";

// What to SHOW: the token's signed `permissions` claim. Up to 15 minutes old.
if (showsPermission(session, "app.people.open")) drawTile();

// What to OPEN or WRITE: the hub, now, server to server, with THIS app's key.
const permissions = createPermissionCheck({
  hubUrl: process.env.AUTH_HOST_URL!,
  serviceKey: process.env.HUB_PERMISSION_CHECK_KEY, // this app's own key, server only
});
const now = await permissions.check(personFromSession(session), "some.permission");
if (now !== "held") return refuse(); // ⛔ "unavailable" is NO
```

| | Reads | Fresh | Decides |
|---|---|---|---|
| `showsPermission(session, key)` | the verified token's `permissions` claim | up to 15 minutes old | ⛔ nothing: navigation and display only |
| `check(person, key)` | `POST /permissions/check` on the hub | this moment | ✅ writes, and reads of student records or money |

- `session.permissions` is `null` when the hub sent no claim (an older hub, the
  claim switched off, or a read that failed) and `[]` when it sent an empty
  one. Both show nothing.
- `check` answers `held`, `not_held` or `unavailable`, never a boolean, never
  throws and never caches. ⛔ Anything but `held` is no. Every status but a
  200 is `unavailable`: a 401 means this app's key is wrong, a 403 a form this
  app may not use, a 503 the hub unable to answer, and none of those says
  anything about the person. A missing or malformed key is `unavailable`
  without calling the hub. Waits 4 seconds.
- Who to ask about: `personFromSession(session)`, the login the hub signed into
  the token. A caller with no signed-in person (a Slack handler) may pass
  `{ address }`, a CGSI-issued address, only if the hub has named that app for
  it.
- 🔴 A yes for a permission held on a caseload or on disciplines means "for
  some records". Necessary, not sufficient: the app still applies the scope.
- The package reads no environment variable. The app passes its key in.

## Cookies

`__Host-cgsi.session`, `__Host-cgsi.session-handle`,
`__Host-cgsi.session-apps` (and three short-lived helpers). Host-only,
HttpOnly, Secure, SameSite=Lax. Never a parent domain.

## Changes

### Unreleased: permissions from the access model

- `AppSession.permissions` (the token's signed claim, or `null`) and
  `showsPermission`, for display only.
- `createPermissionCheck` and `personFromSession`: the live check, server to
  server, with the app's own key. Fails closed.
- Nothing else changed. Against a hub that sends no claim, sessions read
  exactly as before, with `permissions: null`.
- The version number is settled when this merges, beside the capability
  changes.

### 0.1.3

- The launcher's list of apps, when the hub sends one, is stored in
  `__Host-cgsi.session-apps` and read with `readLauncherApps`. ⛔ Unsigned and
  for display only: nothing here uses it to decide anything, and nor should an
  app. See **The launcher's list of apps** above.
- A hub that sends no list, or one this package cannot use, leaves no list.
  Absent is not the same as empty, and an app can tell them apart while it
  moves off its old source.
- Nothing else changed. Against a hub that does not send the list, 0.1.3
  behaves exactly as 0.1.2 did.

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
