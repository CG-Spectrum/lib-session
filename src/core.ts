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
  };
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
    expiresAt: p.exp,
  };
}
