// The one function an app's middleware (Proxy) calls.
//
//   const r = await appSession.handle(req, { legacySignedIn: !!req.auth });
//   if (r) return r;          // this package dealt with the request
//   ...the app's existing shared-cookie behaviour...
//
// `null` means "not mine": in `shared` always; in `both` whenever the person
// has no app session of their own (the shared cookie carries on deciding).
// In `own` it never returns null for a page that needs a session.
import { NextResponse, type NextRequest } from "next/server";
import {
  COOKIE_MAX_AGE_SECONDS, GRACE_HEADER, HUB_DOWN_GRACE_SECONDS, RENEW_EARLY_SECONDS, RETRY_AFTER_SECONDS,
  STATE_TTL_SECONDS, challengeFor, cookieNames, isPageNavigation, originAllowed, randomValue, readPending,
  type OriginGuardMode, type SessionMode,
} from "./core";
import { createHub, type Hub, type HubOptions } from "./hub";

export interface AppSessionOptions extends HubOptions {
  mode: SessionMode;
  originGuard: OriginGuardMode;
  /** true in production: https-only, host-only cookies. */
  secure: boolean;
  /** Other origins allowed to send writes (exact). */
  allowedOrigins?: readonly string[];
  /** Cookie names that mean "a person is signed in the old way" (for the origin guard). */
  legacyCookieNames?: readonly string[];
  /** Paths that need no session (webhooks, cron). Exact, or a prefix ending in "/". */
  publicPaths?: readonly string[];
  callbackPath?: string;
  signOutPath?: string;
  log?: (message: string) => void;
}

export interface HandleContext {
  /** Is the person signed in by the shared cookie? Only read in `both`. */
  legacySignedIn?: boolean;
}

export function createSessionMiddleware(o: AppSessionOptions, hub: Hub = createHub(o)) {
  const names = cookieNames(o.secure);
  const callbackPath = o.callbackPath ?? "/session/callback";
  const signOutPath = o.signOutPath ?? "/session/signout";
  const log = o.log ?? ((m: string) => console.warn(`[session] ${m}`));
  const cookie = (maxAge: number) =>
    ({ httpOnly: true, secure: o.secure, sameSite: "lax" as const, path: "/", maxAge });
  const isPublic = (path: string) =>
    (o.publicPaths ?? []).some((p) => (p.endsWith("/") ? path.startsWith(p) : path === p));

  const clearOwn = (res: NextResponse) => {
    res.cookies.set(names.token, "", cookie(0));
    res.cookies.set(names.handle, "", cookie(0));
    return res;
  };
  const noStore = (res: NextResponse) => {
    res.headers.set("Cache-Control", "no-store");
    return res;
  };

  /** Pass the request on, with a fresh token if one was just issued. */
  function pass(req: NextRequest, fresh?: { token: string; handle: string }, grace = false) {
    const headers = new Headers(req.headers);
    headers.delete(GRACE_HEADER); // never trust one a browser sent
    if (grace) headers.set(GRACE_HEADER, "1");
    if (fresh) {
      // Server code reads cookies from the REQUEST: give it the new token now,
      // not on the next request.
      const jar = new Map(req.cookies.getAll().map((c) => [c.name, c.value]));
      jar.set(names.token, fresh.token);
      jar.set(names.handle, fresh.handle);
      headers.set("cookie", [...jar].map(([k, v]) => `${k}=${v}`).join("; "));
    }
    const res = NextResponse.next({ request: { headers } });
    if (fresh) {
      res.cookies.set(names.token, fresh.token, cookie(COOKIE_MAX_AGE_SECONDS));
      res.cookies.set(names.handle, fresh.handle, cookie(COOKIE_MAX_AGE_SECONDS));
    }
    return res;
  }

  async function startSignIn(req: NextRequest, markTried: boolean) {
    const state = randomValue(24);
    const verifier = randomValue(32);
    const returnTo = req.nextUrl.pathname + req.nextUrl.search;
    const res = noStore(NextResponse.redirect(hub.authorizeUrl(state, await challengeFor(verifier))));
    res.cookies.set(names.state, JSON.stringify({ s: state, v: verifier, r: returnTo }), cookie(STATE_TTL_SECONDS));
    if (markTried) res.cookies.set(names.tried, "1", cookie(RETRY_AFTER_SECONDS));
    return res;
  }

  async function finishSignIn(req: NextRequest) {
    const pending = readPending(req.cookies.get(names.state)?.value);
    const code = req.nextUrl.searchParams.get("code");
    const state = req.nextUrl.searchParams.get("state");
    const back = (to: string) => {
      const res = noStore(NextResponse.redirect(new URL(to, req.nextUrl.origin)));
      res.cookies.set(names.state, "", cookie(0));
      return res;
    };
    const failed = (why: string) => {
      log(`sign-in not completed: ${why}`);
      // `both`: the shared cookie carries on; the `tried` cookie stops a loop.
      if (o.mode === "both") return back(pending?.r ?? "/");
      const res = noStore(new NextResponse("Sign-in could not be completed. Go back and try again.", { status: 401 }));
      res.cookies.set(names.state, "", cookie(0));
      return res;
    };
    if (!pending || !code || !state || state !== pending.s) return failed("state");
    const granted = await hub.exchange(code, pending.v);
    if (!granted.ok) return failed(granted.reason);
    // Never store what this app would not itself accept.
    if ((await hub.check(granted.token)).state !== "valid") return failed("token");
    const res = back(pending.r);
    res.cookies.set(names.token, granted.token, cookie(COOKIE_MAX_AGE_SECONDS));
    res.cookies.set(names.handle, granted.handle, cookie(COOKIE_MAX_AGE_SECONDS));
    res.cookies.set(names.tried, "", cookie(0));
    return res;
  }

  return async function handle(req: NextRequest, ctx: HandleContext = {}): Promise<NextResponse | null> {
    const path = req.nextUrl.pathname;
    const token = req.cookies.get(names.token)?.value;
    const handleValue = req.cookies.get(names.handle)?.value;

    // ── Writes must come from this app's own pages (any mode, when on) ──────
    if (o.originGuard !== "off") {
      const signedIn = !!token || (o.legacyCookieNames ?? []).some((n) => req.cookies.has(n));
      if (signedIn && !originAllowed({
        method: req.method, origin: req.headers.get("origin"), secFetchSite: req.headers.get("sec-fetch-site"),
        host: req.nextUrl.host, allowed: o.allowedOrigins,
      })) {
        log(`write from another origin ${o.originGuard === "enforce" ? "refused" : "seen (report only)"}: ${req.method} ${path}`);
        if (o.originGuard === "enforce") return noStore(new NextResponse("Forbidden", { status: 403 }));
      }
    }

    if (o.mode === "shared") return null;

    if (path === signOutPath) {
      // Come back to the page the person was on, if it is one of this app's.
      let after = req.nextUrl.origin;
      const wanted = req.nextUrl.searchParams.get("callbackUrl");
      if (wanted) {
        try {
          const asked = new URL(wanted, req.nextUrl.origin);
          if (asked.origin === req.nextUrl.origin) after = asked.toString();
        } catch { /* keep the app's front page */ }
      }
      const res = clearOwn(noStore(NextResponse.redirect(hub.signOutUrl(after))));
      res.cookies.set(names.tried, "", cookie(0));
      return res;
    }
    if (path === callbackPath) return finishSignIn(req);
    if (isPublic(path)) return null;

    // ── The app's own session ───────────────────────────────────────────────
    let dead = false;
    if (token) {
      const checked = await hub.check(token);
      if (checked.state === "valid" && checked.secondsLeft > RENEW_EARLY_SECONDS) return pass(req);
      if (checked.state !== "invalid" && handleValue) {
        const renewed = await hub.renew(handleValue);
        if (renewed.ok) return pass(req, renewed);
        if (renewed.reason === "no_access") {
          // The person may no longer open this app. No fallback, in any mode.
          return clearOwn(noStore(
            req.method === "GET" ? NextResponse.redirect(hub.noAccessUrl()) : new NextResponse("Forbidden", { status: 403 }),
          ));
        }
        if (renewed.reason === "unreachable") {
          if (checked.state === "valid") return pass(req);
          if (checked.expiredForSeconds <= HUB_DOWN_GRACE_SECONDS) return pass(req, undefined, true);
        }
      } else if (checked.state === "valid") {
        return pass(req); // no handle to renew with: good until it runs out
      }
      dead = true;
    }

    // ── No session of its own ───────────────────────────────────────────────
    if (o.mode === "both") {
      const canTry =
        ctx.legacySignedIn === true && isPageNavigation(req.method, req.headers) &&
        !req.cookies.has(names.tried) && (await hub.available());
      if (canTry) return clearOwn(await startSignIn(req, true));
      if (!dead) return null;
      // Hand over to the shared cookie, dropping the dead session on the way.
      const res = pass(req);
      return clearOwn(res);
    }
    if (req.method !== "GET") return clearOwn(noStore(new NextResponse("Signed out", { status: 401 })));
    return clearOwn(await startSignIn(req, false));
  };
}
