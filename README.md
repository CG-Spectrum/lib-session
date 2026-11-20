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
import { hasCapability } from "@cgsi/session";
import { readAppSession, readLauncherApps } from "@cgsi/session/server";
const session = await readAppSession(hub, secure, await cookies(), await headers());
const mayExport = hasCapability(session, "exports");          // signed: may decide
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

## This app's own capabilities

Some apps decide a second thing from a second grant: a page only some people
may open, an editor only some people may use. The hub signs those keys into
the token as `caps`, and this package reads them into `session.capabilities`.

```ts
if (!hasCapability(session, "exports")) return notFound();
```

**✅ Signed, so it may decide.** It comes from the token the hub signed for
this app and nothing else. A null session is `false`, so a gate written this
way fails closed without the caller remembering to check.

What the hub will and will not put in it:

- Only keys **this app** declared in the hub's registry, and only those the
  person actually holds. An app is never told about another app's key, however
  many the person holds, so a capability says what this person may do here and
  nothing at all about anywhere else.
- An empty list and no list are **the same answer**: no capabilities. A
  capability has no older source to fall back to, so either the signed token
  says the person has it or they do not. There is deliberately no `null` here
  to tell apart (the launcher's list below is the opposite case, and keeps its
  distinction for exactly that reason).
- An older hub sends no claim at all, which is the same empty answer, and
  everything else behaves exactly as 0.1.3.
- Anything unreadable in the claim is no capabilities. It never throws and it
  never costs the person the session: a list of at most 24 app keys
  (`^[a-z][a-z0-9-]{1,40}$`) or nothing.

### ⛔ Not the launcher's list

The two are easy to say in one breath and must never be used in one:

| | `session.capabilities` | `readLauncherApps(...)` |
|---|---|---|
| Comes from | the verified token | a cookie |
| Signed | ✅ yes, by the hub, for this app | ⛔ no |
| May decide | ✅ yes | ⛔ never |
| About | what this person may do **here** | which tiles to draw |
| Absent | the same as empty | `null`, which is not `[]` |

They have different names, different sources and different functions, and one
is a field of `AppSession` while the other can never be. If the question is
"may this person do X", the answer is `hasCapability`.

## Asking at the moment of the decision

The signed claim above is re-read whenever the token is renewed, so it is up to
15 minutes old. That is the right answer for deciding what to **show** and the
wrong one for deciding what to **open**. For a key over money or personal
records, ask the hub at the moment the app decides:

```ts
import { hasCapability } from "@cgsi/session";
import { checkCapabilityNow, readAppSession } from "@cgsi/session/server";

const session = await readAppSession(hub, secure, await cookies(), await headers());
const show = hasCapability(session, "values");        // the tab, the menu item

// ...and when the person actually opens it, or writes:
const now = await checkCapabilityNow(hub, secure, await cookies(), await headers(), "values");
if (now !== "held") return tryAgain();                // ⛔ "unavailable" is NO
```

**⛔ It answers a word, never a boolean.** An app handed `true | false` has
nowhere to put "the hub could not be asked", and what it will do with that
nowhere is treat it as one of the two.

| Answer | Means | For a sensitive key |
|---|---|---|
| `"held"` | the hub said yes, in this call, just now | the only yes |
| `"not_held"` | the hub said no, or there is nothing to ask with | no |
| `"unavailable"` | the hub could not be asked, or did not answer usefully | **no** |

**Which to use when:**

| | `hasCapability(session, key)` | `checkCapabilityNow(...)` |
|---|---|---|
| Source | the signed token | the hub, in this call |
| Age | up to 15 minutes | now |
| Cost | none | one request, up to 4 seconds |
| Decides | what to **show** | what to **open** or **write** |
| When the hub is unreachable | the claim still answers | `"unavailable"`, which is no |

A key over money or personal records needs **both**: the claim to draw the tab,
the live check to serve the page or take the write. Showing a tab that then
refuses is a cosmetic cost; opening a record on a grant withdrawn fourteen
minutes ago is not.

What it does, exactly:

- Presents the token **this request** holds. A renewal on this same request
  hands server code the new token, and this reads it from that same place, so
  a just-renewed session never presents the token the hub has moved on from.
- No token, an expired one, or one this app would not itself accept is
  `"not_held"` **without calling the hub**.
- ⛔ **The grace period does not apply.** An expired token is honoured for up
  to an hour when the hub cannot be reached (see **The grace period**); a
  request on that path is `"not_held"` here, and the hub is not asked.
- A timeout, a network failure, a `4xx`, a `5xx`, or a body it cannot read are
  all `"unavailable"`. Only a `200` saying `true`, in this call, is `"held"`.
- ⛔ It never throws, and it never logs a value: a reason word only.
- The short pause renewals take after a hub failure does **not** apply to it,
  and it does not lengthen that pause. A sensitive decision is rare beside a
  renewal, so it adds no flood; and nothing but a real `200` is ever `"held"`,
  so the pause is not what makes it safe.
- Its own deadline, `HUB_CAPABILITY_TIMEOUT_MS`, 4 seconds: half the `/token`
  wait, because the hub bounds its own work on this call far more tightly, and
  because waiting longer only makes the person wait longer for the same no.

The hub side is `POST /capability` on the sign-in hub, which answers from a
fresh read of the person's grants by the same rule it signs the claim with. It
needs no new secret: the app presents the token the hub signed for it.

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

## Cookies

`__Host-cgsi.session`, `__Host-cgsi.session-handle`,
`__Host-cgsi.session-apps` (and three short-lived helpers). Host-only,
HttpOnly, Secure, SameSite=Lax. Never a parent domain.

## Changes

### 0.1.5

- `checkCapabilityNow(hub, secure, cookies, headers, key)`: asks the hub
  whether this person holds this key RIGHT NOW, and answers `"held"`,
  `"not_held"` or `"unavailable"`. ⛔ Never a boolean, and for a sensitive key
  anything but `"held"` is no. See **Asking at the moment of the decision**.
- It presents the token this request holds, so a session renewed on the same
  request is checked on its new token.
- ⛔ Fails closed: no grace, no benefit of the doubt. The hub-down grace that
  carries an expired token for up to an hour does not apply, and no failure of
  any kind can produce `"held"`.
- `hub.checkCapability(token, key)` beside it, for an app that has already
  found the token itself. `HubOptions.log` is where its reason word goes.
- Nothing else changed. An app that calls neither behaves exactly as 0.1.4,
  and no hub call is made that was not made before.

### 0.1.4

- `session.capabilities`: this app's own sub-grant keys, from the **verified**
  token's `caps` claim, with `hasCapability(session, key)` beside it. ✅ This
  is the one that may decide something. See **This app's own capabilities**.
- Absent, unreadable, or anything in it that is not an app key, all mean no
  capabilities. Never an error, never a refused session.
- Against a hub that does not send the claim, 0.1.4 behaves exactly as 0.1.3
  did, with `capabilities` empty on every session.
- ⛔ The launcher's list is unchanged and still decides nothing. The two are
  set out side by side above so they cannot be mistaken for one another.

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
