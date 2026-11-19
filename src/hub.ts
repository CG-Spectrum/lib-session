// Talking to the sign-in hub: checking a token, and the two /token calls.
import { createRemoteJWKSet, customFetch, errors, jwtVerify, type JWTVerifyGetKey } from "jose";
import { sessionFromClaims, type AppSession } from "./core";

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
  | { ok: true; token: string; handle: string }
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

  async function grant(body: Record<string, string>): Promise<TokenGrant> {
    let res: Response;
    try {
      res = await doFetch(`${base}/token`, {
        method: "POST", cache: "no-store", signal: AbortSignal.timeout(4000),
        headers: { ...headers, "content-type": "application/json" },
        body: JSON.stringify({ app: o.app, ...body }),
      });
    } catch {
      return { ok: false, reason: "unreachable" };
    }
    if (res.status === 401) return { ok: false, reason: "invalid" };
    if (res.status === 403) return { ok: false, reason: "no_access" };
    if (res.status !== 200) return { ok: false, reason: "unreachable" };
    try {
      const j = (await res.json()) as { token?: unknown; handle?: unknown };
      if (typeof j.token !== "string" || typeof j.handle !== "string") return { ok: false, reason: "unreachable" };
      return { ok: true, token: j.token, handle: j.handle };
    } catch {
      return { ok: false, reason: "unreachable" };
    }
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
    exchange: (code, verifier) => grant({ grant: "code", code, verifier }),
    renew: (handle) => grant({ grant: "renew", handle }),
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
