// @cgsi/session: the rules, with no framework in sight.
//
// An app holds a 15-minute token the sign-in hub signed FOR THAT APP, in a
// cookie only that app's host receives, and renews it at the hub. The app can
// check a token and can never make one.
//
// Web Crypto and fetch only: runs the same in Proxy/middleware, on a server
// and in tests.

/**
 * shared  today: the hub's cookie on the parent domain decides. This package
 *         does nothing.
 * both    the app's own session when there is one, otherwise the shared
 *         cookie. Nothing is ever refused that `shared` would allow.
 * own     the app's own session only.
 * Anything else, a typo included, is `shared`: a mistake changes nothing.
 */
export type SessionMode = "shared" | "both" | "own";
export function sessionMode(raw: string | undefined): SessionMode {
  const v = (raw ?? "").trim().toLowerCase();
  return v === "both" || v === "own" ? v : "shared";
}

export type OriginGuardMode = "off" | "report" | "enforce";
/** Unset: off while `shared` (nothing changes on install), enforce otherwise. */
export function originGuardMode(raw: string | undefined, mode: SessionMode): OriginGuardMode {
  const v = (raw ?? "").trim().toLowerCase();
  if (v === "off" || v === "report" || v === "enforce") return v;
  return mode === "shared" ? "off" : "enforce";
}

// How long to wait for the hub's answer on a /token call.
//
// The app's clock starts before the hub's handler does. A cold start on either
// side can use up most of a short wait, and the hub can then answer just after
// the app has given up, having already acted on what it was sent. Waiting
// longer costs little: a hub that is really down is remembered as busy after
// the first failure, so the wait is paid once and not by every request.
export const HUB_TOKEN_TIMEOUT_MS = 8000;
// Renew this long before a token runs out, so a page never starts with one
// about to expire.
export const RENEW_EARLY_SECONDS = 60;
// If the hub cannot be REACHED (never: if it refuses), keep honouring the last
// token for this long.
export const HUB_DOWN_GRACE_SECONDS = 60 * 60;
// After one failed attempt to move a person onto the app's own session, leave
// them on the shared cookie for this long before trying again (`both` only).
export const RETRY_AFTER_SECONDS = 5 * 60;
export const STATE_TTL_SECONDS = 10 * 60;
export const COOKIE_MAX_AGE_SECONDS = 30 * 24 * 60 * 60;

/** __Host- means: this host only, never a parent domain. It needs https. */
export function cookieNames(secure: boolean) {
  const p = secure ? "__Host-" : "";
  return {
    token: `${p}cgsi.session`,
    handle: `${p}cgsi.session-handle`,
    state: `${p}cgsi.session-state`,
    tried: `${p}cgsi.session-tried`,
    // One fresh sign-in has already been started because the hub could not
    // answer. Lives as long as a pending sign-in can (STATE_TTL_SECONDS), so a
    // second one cannot be started while the first is still good.
    restarted: `${p}cgsi.session-restarted`,
    // The launcher's list of apps. ⛔ UNSIGNED: see below.
    apps: `${p}cgsi.session-apps`,
  };
}

// ── The launcher's list of apps ─────────────────────────────────────────────
// ⛔ A DISPLAY LIST. IT DECIDES NOTHING, HERE OR ANYWHERE.
//
// The hub sends the person's app keys beside the token at every grant and
// renewal, so a launcher can draw tiles. It is deliberately NOT a claim in the
// token, so nothing about it is signed: it sits in a cookie, and a person who
// opens their own browser's storage can put whatever they like in it. The most
// it can ever do is show somebody a tile that will refuse them when they click
// it, which is what happens today anyway when a grant is taken away.
//
// ⛔ Nothing in this package reads it to decide anything, and nothing in an app
// may either. If a question is "may this person do X", the answer is the
// token's claims or the app's own gate, never this.
//
// It is called `launcherApps` everywhere, in the type and in the API, so that
// no reader can mistake it for the authorisation it is not.
//
// Stored as the keys joined by ".", behind one leading ".", which is plain to
// read, needs no escaping in a cookie value, and tells an EMPTY list (".") from
// NO list at all (no cookie, or nonsense in it). An app moving off the shared
// cookie has to be able to tell those two apart.
const LAUNCHER_APP_KEY = /^[a-z][a-z0-9-]{1,40}$/;
/**
 * The most keys a list may hold. The estate's whole catalogue is 24 today
 * (the hub's own canonical order), so this is room to grow and still a bound.
 */
export const LAUNCHER_APPS_MAX_COUNT = 40;
/**
 * The most the stored value may be, in bytes. Keys are ASCII by their own
 * rule above, so one character is one byte. The worst realistic list, all 24
 * of today's keys, is 262 bytes, and a browser allows about 4096 per cookie,
 * so this is several times the real worst case and still a long way inside
 * what a browser will carry.
 */
export const LAUNCHER_APPS_MAX_BYTES = 1024;

const encoded = (apps: readonly string[]): string => `.${apps.join(".")}`;

/**
 * A list of app keys, or null if this is not one. ⛔ Never throws, whatever it
 * is handed: an unusable value is an ABSENT list, never an error and never an
 * empty one.
 */
export function launcherAppsFrom(value: unknown): string[] | null {
  if (!Array.isArray(value) || value.length > LAUNCHER_APPS_MAX_COUNT) return null;
  const apps: string[] = [];
  for (const v of value) {
    if (typeof v !== "string" || !LAUNCHER_APP_KEY.test(v)) return null;
    apps.push(v);
  }
  return encoded(apps).length > LAUNCHER_APPS_MAX_BYTES ? null : apps;
}

/** The cookie value for a list that `launcherAppsFrom` has already accepted. */
export function encodeLauncherApps(apps: readonly string[]): string {
  return encoded(apps);
}

/** What a cookie holds, read back. Null means no list, which is not an empty one. */
export function parseLauncherApps(raw: string | undefined): string[] | null {
  if (typeof raw !== "string" || raw[0] !== "." || raw.length > LAUNCHER_APPS_MAX_BYTES) return null;
  return raw === "." ? [] : launcherAppsFrom(raw.slice(1).split("."));
}

// ── This app's own capabilities ─────────────────────────────────────────────
// ✅ SIGNED, AND IT IS THE ONE THAT MAY DECIDE.
//
// Several apps make a second decision from a second key: a reports page only
// some people may open, an editor only some people may use. The hub signs
// those keys into the token as `caps`, so an app can decide from them with the
// same confidence it decides anything else from the token.
//
// ⚖️ THE PAIR, SAID ONCE, BECAUSE CONFUSING THEM IS THE WHOLE RISK:
//
//   capabilities   from the VERIFIED token. Signed by the hub, for this app
//                  alone. ✅ May decide. Reached through `hasCapability` or
//                  `session.capabilities`.
//   launcherApps   from a COOKIE. Unsigned; a person can put anything in it.
//                  ⛔ May not decide anything, ever. Reached through
//                  `readLauncherApps`, which is deliberately not part of a
//                  session at all.
//
// They are named differently, they are read through different functions, and
// one is a field of `AppSession` while the other can never be. If a reader has
// to think about which is which, this file has failed.
//
// ⚖️ WHAT THE HUB WILL AND WILL NOT PUT IN IT. Only keys the asking app has
// declared in the hub's registry, and only those the person actually holds. An
// app is never told about a key belonging to another app, however many the
// person holds, so a capability says what this person may do HERE and nothing
// about anywhere else.
const CAPABILITY_KEY = /^[a-z][a-z0-9-]{1,40}$/;
/**
 * The most keys a token may carry. One app's own sub-grants are a handful
 * today; this is room to grow and still a bound on a claim this package did
 * not write.
 */
export const CAPABILITIES_MAX_COUNT = 24;

/**
 * The capabilities in a verified token's claims.
 *
 * ⛔ FAILS CLOSED AND NEVER THROWS. Absent (an older hub), not an array, or
 * anything in it that is not an app key, all mean NO capabilities. There is no
 * "absent" answer to tell from "empty" here, on purpose: a capability has no
 * older source to fall back to, so either the signed token says the person has
 * it or they do not. One meaning, and it is the safe one.
 */
export function capabilitiesFrom(value: unknown): string[] {
  if (!Array.isArray(value) || value.length > CAPABILITIES_MAX_COUNT) return [];
  const caps: string[] = [];
  for (const v of value) {
    if (typeof v !== "string" || !CAPABILITY_KEY.test(v)) return [];
    caps.push(v);
  }
  return caps;
}

/** Set by the middleware on the request it passes on; any value a browser sent is removed first. */
export const GRACE_HEADER = "x-cgsi-session-grace";

const b64url = (bytes: Uint8Array): string => {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};
export function randomValue(byteLength = 32): string {
  return b64url(crypto.getRandomValues(new Uint8Array(byteLength)));
}
export async function challengeFor(verifier: string): Promise<string> {
  return b64url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))));
}

/** Where to send the person afterwards: a path on this app, never another site. */
export function safeReturnTo(raw: unknown): string {
  if (typeof raw !== "string" || !raw.startsWith("/") || raw.startsWith("//") || raw.includes("\\")) return "/";
  // Control characters have no place in a path and can confuse a redirect.
  for (let i = 0; i < raw.length; i++) if (raw.charCodeAt(i) < 0x20) return "/";
  return raw;
}

export interface PendingSignIn { s: string; v: string; r: string }
export function readPending(raw: string | undefined): PendingSignIn | null {
  try {
    const v = JSON.parse(raw ?? "") as Partial<PendingSignIn>;
    return typeof v.s === "string" && typeof v.v === "string" && typeof v.r === "string"
      ? { s: v.s, v: v.v, r: safeReturnTo(v.r) }
      : null;
  } catch {
    return null;
  }
}

// ── Requests that change something must come from the app's own pages ───────
// SameSite=Lax stops other SITES. It does not stop a page on another host
// under the same parent domain: to a browser those are the same site. So a
// write must say it came from this very host.
const SAFE = new Set(["GET", "HEAD", "OPTIONS"]);
export function originAllowed(input: {
  method: string;
  /** The Origin header, if the browser sent one. */
  origin: string | null;
  /** The Sec-Fetch-Site header, if the browser sent one. */
  secFetchSite: string | null;
  /** This app's own host, as the request reached it. */
  host: string;
  /** Other origins allowed to call (exact, e.g. "https://home.cgspectrum.com"). */
  allowed?: readonly string[];
}): boolean {
  if (SAFE.has(input.method.toUpperCase())) return true;
  if (input.origin !== null) {
    if (input.allowed?.includes(input.origin)) return true;
    try {
      return new URL(input.origin).host === input.host;
    } catch {
      return false; // "null" (a sandboxed page) and anything unparseable
    }
  }
  // No Origin: a browser's own same-origin request, or not a browser at all
  // (a script holds no person's cookie by accident, so it is not this attack).
  return input.secFetchSite === null || input.secFetchSite === "same-origin" || input.secFetchSite === "none";
}

/** A browser asking for a page, not a background fetch or a prefetch. */
export function isPageNavigation(method: string, headers: { get(name: string): string | null }): boolean {
  if (method.toUpperCase() !== "GET") return false;
  if (headers.get("rsc") || headers.get("next-router-prefetch") || headers.get("purpose") === "prefetch") return false;
  const dest = headers.get("sec-fetch-dest");
  if (dest) return dest === "document";
  return (headers.get("accept") ?? "").includes("text/html");
}

/** What the app sees of the signed-in person. */
export interface AppSession {
  /** The hub session this hangs from. */
  sid: string;
  email: string;
  name: string | null;
  /** The login, exactly as identity.resolve(provider, subject) expects it. */
  subject: string;
  loginProvider: string;
  kind: string;
  role: string;
  departments: string[];
  /** This app's own role for the person, or null. */
  appRole: string | null;
  /**
   * The access model's display permissions, from the token's `permissions`
   * claim, or null when the hub sent none (an older hub, the claim switched
   * off, or a read that failed). ⛔ Display only: see `showsPermission`.
   */
  permissions: string[] | null;
   * ✅ THE SIGNED ONE. This app's own sub-grant keys that the person holds,
   * from the verified token, so it MAY be decided from. Empty when the hub
   * sent none, which includes every hub older than this claim.
   *
   * ⛔ Not to be confused with `readLauncherApps`, which comes from a cookie,
   * is unsigned and may decide nothing. See "This app's own capabilities".
   */
  capabilities: string[];
  /** When the token runs out (seconds since 1970). */
  expiresAt: number;
}

const str = (v: unknown): v is string => typeof v === "string" && v.length > 0;
/** A verified token's claims as an AppSession, or null if anything needed is missing. */
export function sessionFromClaims(p: Record<string, unknown>): AppSession | null {
  if (!str(p.sid) || !str(p.email) || !str(p.gsub) || !str(p.lprov) || !str(p.kind) || !str(p.role)) return null;
  if (typeof p.exp !== "number") return null;
  return {
    sid: p.sid, email: p.email.toLowerCase(), name: str(p.name) ? p.name : null,
    subject: p.gsub, loginProvider: p.lprov, kind: p.kind, role: p.role,
    departments: Array.isArray(p.departments) ? p.departments.filter(str) : [],
    appRole: str(p.appRole) ? p.appRole : null,
    permissions: Array.isArray(p.permissions) ? p.permissions.filter(str) : null,
    // ⛔ A claim this package cannot read is NO capabilities, and never a
    // reason to refuse the session: everything else in the token is still
    // good, and an app on an older hub, which sends no claim at all, goes on
    // working exactly as it did.
    capabilities: capabilitiesFrom(p.caps),
    expiresAt: p.exp,
  };
}

/**
 * Does this person hold one of THIS APP's capabilities?
 *
 *   if (!hasCapability(session, "reports")) return notFound();
 *
 * ✅ The answer comes from the verified token and nowhere else. Nobody is
 * signed in (a null session) is false, so a gate written this way fails closed
 * without the caller remembering to check.
 */
export function hasCapability(session: AppSession | null | undefined, key: string): boolean {
  return !!session && session.capabilities.includes(key);
}
