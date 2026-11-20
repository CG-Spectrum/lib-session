// Talking to the sign-in hub: checking a token, and the two /token calls.
import { createRemoteJWKSet, customFetch, errors, jwtVerify, type JWTVerifyGetKey } from "jose";
import { HUB_TOKEN_TIMEOUT_MS, launcherAppsFrom, sessionFromClaims, type AppSession } from "./core";

export interface HubOptions {
  /** This app's key in the hub's registry, e.g. "console". */
  app: string;
  /** The hub, e.g. https://auth.cgspectrum.com. */
  hubUrl: string;
  /** Who signs. Defaults to hubUrl. Staging has its own. */
  issuer?: string;
  /** Extra headers on server-to-server calls to the hub. */
  hubHeaders?: Record<string, string>;
  /** For tests. */
  fetch?: typeof fetch;
  now?: () => number;
}

export type TokenCheck =
  | { state: "valid"; session: AppSession; secondsLeft: number }
  /** Signed by the hub for this app, but past its time. */
  | { state: "expired"; session: AppSession; expiredForSeconds: number }
  | { state: "invalid" };

export type TokenGrant =
  | {
      ok: true;
      token: string;
      handle: string;
      /**
       * The launcher's list of apps, or null when the hub sent none it could
       * use. ⛔ UNSIGNED AND FOR DISPLAY ONLY (see core.ts). Null is "the hub
       * said nothing", which is not the same as "the hub said none".
       */
      launcherApps: string[] | null;
    }
  /** The hub answered and said no: sign in again (invalid) or not allowed (no_access). */
  | { ok: false; reason: "invalid" | "no_access" }
  /** The hub could not be reached, or is broken. Not a refusal. */
  | { ok: false; reason: "unreachable" };

export interface Hub {
  check(token: string | undefined): Promise<TokenCheck>;
  exchange(code: string, verifier: string): Promise<TokenGrant>;
  renew(handle: string): Promise<TokenGrant>;
  /** Is the hub offering per-app sessions at all? Cached. */
  available(): Promise<boolean>;
  authorizeUrl(state: string, challenge: string): string;
  signOutUrl(returnTo: string): string;
  noAccessUrl(): string;
}

// ── When the hub has nothing to give ─────────────────────────────────────────
// A /token call ends as `unreachable` when the hub times out, the network
// fails, or the hub answers that it is busy. The hub spends nothing on such an
// answer, so the code or handle that was sent is still good.
//
// How long to wait before asking again. A hub that says `Retry-After` in whole
// seconds is believed, within these bounds; anything else (a date, nonsense,
// no header at all, no answer at all) waits the shortest time.
const BUSY_MIN_MS = 1000;
const BUSY_MAX_MS = 5000;
function busyForMs(res: Response | null): number {
  const raw = res?.headers.get("retry-after")?.trim();
  if (raw && /^\d{1,6}$/.test(raw)) {
    return Math.min(Math.max(Number(raw) * 1000, BUSY_MIN_MS), BUSY_MAX_MS);
  }
  return BUSY_MIN_MS;
}

// How long one renewal's answer stays available to other requests carrying the
// SAME handle, after the call it came from has finished.
const SHARE_RENEWAL_MS = 3000;
// At most this many handles are remembered at once, so a busy instance cannot
// grow the map without bound. The oldest entry goes first.
const MAX_SHARED_RENEWALS = 100;

/** SHA-256, so the map holds a fingerprint of a handle and never the handle. */
async function fingerprint(value: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));
  let s = "";
  for (const b of digest) s += String.fromCharCode(b);
  return btoa(s);
}

export function createHub(o: HubOptions): Hub {
  const base = o.hubUrl.replace(/\/$/, "");
  const issuer = (o.issuer ?? base).replace(/\/$/, "");
  const doFetch: typeof fetch = o.fetch ?? ((...a) => fetch(...a));
  const now = o.now ?? (() => Date.now());
  const headers = o.hubHeaders ?? {};

  let jwks: JWTVerifyGetKey | null = null;
  const keys = () =>
    (jwks ??= createRemoteJWKSet(new URL(`${base}/.well-known/jwks.json`), {
      cacheMaxAge: 10 * 60 * 1000, cooldownDuration: 30 * 1000, timeoutDuration: 3000, headers,
      [customFetch]: doFetch,
    }));

  let seen: { ok: boolean; until: number } | null = null;

  // In memory, in this instance only. Nothing here is shared between processes
  // and nothing survives a restart: it is a few seconds of good manners
  // towards a hub that is already behind, not a cache of anything.
  let busyUntil = 0;
  type SharedRenewal = { grant: Promise<TokenGrant>; until: number };
  const sharedRenewals = new Map<string, SharedRenewal>();

  /** The hub gave nothing. Hold off on renewals for a moment. */
  function nothingToGive(res: Response | null): TokenGrant {
    busyUntil = Math.max(busyUntil, now() + busyForMs(res));
    return { ok: false, reason: "unreachable" };
  }

  async function grant(body: Record<string, string>): Promise<TokenGrant> {
    let res: Response;
    try {
      res = await doFetch(`${base}/token`, {
        method: "POST", cache: "no-store", signal: AbortSignal.timeout(HUB_TOKEN_TIMEOUT_MS),
        headers: { ...headers, "content-type": "application/json" },
        body: JSON.stringify({ app: o.app, ...body }),
      });
    } catch {
      return nothingToGive(null);
    }
    if (res.status === 401) return { ok: false, reason: "invalid" };
    if (res.status === 403) return { ok: false, reason: "no_access" };
    if (res.status !== 200) return nothingToGive(res);
    try {
      const j = (await res.json()) as { token?: unknown; handle?: unknown; apps?: unknown };
      if (typeof j.token !== "string" || typeof j.handle !== "string") return nothingToGive(res);
      // A hub that does not send `apps` at all, and anything that is not a
      // sound list of app keys, both come out as null: no list. ⛔ Never an
      // empty one, and never a reason to fail the grant. The token is what a
      // grant is for; the launcher's list is decoration on top of it.
      return { ok: true, token: j.token, handle: j.handle, launcherApps: launcherAppsFrom(j.apps) };
    } catch {
      return nothingToGive(res);
    }
  }

  /**
   * One renewal per handle at a time.
   *
   * A single page load makes several requests at once, all carrying the same
   * handle cookie, and all of them can arrive in the last minute of the token.
   * They are one browser session asking one question, so they make one call
   * and share its answer. A NEW TOKEN stays available for a few seconds after
   * the call finishes, because requests that set off with the same old cookie
   * are still arriving. Anything else is dropped the moment the call ends: a
   * refusal must reach the next request at once, so that a session the hub has
   * ended is not carried for another few seconds.
   *
   * Sharing is safe because a handle IS the session: it lives in a host-only
   * HttpOnly cookie that only that browser holds, so a token issued for it
   * belongs to whoever presented it. It would stop being safe if handles were
   * ever shared between people or apps, if the hub made the token depend on
   * anything but the handle (something per-request, say), or if each caller
   * had to receive its own single-use handle. Any of those, and this must go.
   */
  function renewOnce(handle: string, key: string): Promise<TokenGrant> {
    const open = sharedRenewals.get(key);
    if (open && open.until > now()) return open.grant;
    for (const [k, v] of sharedRenewals) if (v.until <= now()) sharedRenewals.delete(k);
    if (sharedRenewals.size >= MAX_SHARED_RENEWALS) {
      const oldest = sharedRenewals.keys().next();
      if (!oldest.done) sharedRenewals.delete(oldest.value);
    }
    // Infinity while the call is in flight: waiters must not start a second
    // call because the sharing window ran out mid-call.
    const entry: SharedRenewal = { grant: grant({ grant: "renew", handle }), until: Number.POSITIVE_INFINITY };
    sharedRenewals.set(key, entry);
    const done = (held: boolean) => {
      if (held) entry.until = now() + SHARE_RENEWAL_MS;
      else if (sharedRenewals.get(key) === entry) sharedRenewals.delete(key);
    };
    entry.grant.then((r) => done(r.ok), () => done(false));
    return entry.grant;
  }

  return {
    async check(token) {
      if (!token) return { state: "invalid" };
      const currentDate = new Date(now());
      try {
        // Signature, issuer, the ONE app it is for, and its time. A token for
        // another app, from another hub, or in another algorithm is refused.
        const { payload } = await jwtVerify(token, keys(), {
          issuer, audience: o.app, algorithms: ["ES256"], clockTolerance: 5, currentDate,
          requiredClaims: ["exp", "iat"],
        });
        const session = sessionFromClaims(payload);
        if (!session) return { state: "invalid" };
        return { state: "valid", session, secondsLeft: session.expiresAt - Math.floor(now() / 1000) };
      } catch (e) {
        // jose checks the signature BEFORE the time, so an expired error means
        // the token is genuinely the hub's, only old.
        if (e instanceof errors.JWTExpired) {
          const session = sessionFromClaims(e.payload);
          if (session) return { state: "expired", session, expiredForSeconds: Math.floor(now() / 1000) - session.expiresAt };
        }
        return { state: "invalid" };
      }
    },
    // Finishing a sign-in is NOT held off while the hub is busy. A person at
    // the end of a sign-in gets one attempt, and refusing it on the strength
    // of some other request's failure a moment ago turns a slow hub into a
    // dead end for them. There is one of these per sign-in, against many
    // renewals per page load, so it adds nothing worth saving.
    exchange: (code, verifier) => grant({ grant: "code", code, verifier }),
    async renew(handle) {
      if (busyUntil > now()) return { ok: false, reason: "unreachable" };
      return renewOnce(handle, await fingerprint(handle));
    },
    async available() {
      if (seen && seen.until > now()) return seen.ok;
      let ok = false;
      try {
        const res = await doFetch(`${base}/.well-known/jwks.json`, { headers, cache: "no-store", signal: AbortSignal.timeout(3000) });
        ok = res.status === 200;
      } catch {
        ok = false;
      }
      seen = { ok, until: now() + (ok ? 5 * 60 * 1000 : 60 * 1000) };
      return ok;
    },
    authorizeUrl: (state, challenge) =>
      `${base}/authorize?app=${encodeURIComponent(o.app)}&state=${encodeURIComponent(state)}&challenge=${encodeURIComponent(challenge)}`,
    signOutUrl: (returnTo) => `${base}/signout?callbackUrl=${encodeURIComponent(returnTo)}`,
    noAccessUrl: () => `${base}/no-access?app=${encodeURIComponent(o.app)}`,
  };
}
