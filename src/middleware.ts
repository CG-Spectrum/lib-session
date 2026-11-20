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
  STATE_TTL_SECONDS, challengeFor, cookieNames, encodeLauncherApps, isPageNavigation, originAllowed, randomValue,
  readPending, type OriginGuardMode, type SessionMode,
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
    res.cookies.set(names.apps, "", cookie(0));
    return res;
  };
  /**
   * The launcher's list, stored for exactly as long as the token is. A grant
   * that carried no list CLEARS it rather than leaving the last one behind:
   * the cookie says what the hub last said, and "the hub said nothing" has to
   * stay tellable from "the hub said none".
   */
  const setLauncherApps = (res: NextResponse, apps: string[] | null) =>
    res.cookies.set(names.apps, apps ? encodeLauncherApps(apps) : "", cookie(apps ? COOKIE_MAX_AGE_SECONDS : 0));
  const noStore = (res: NextResponse) => {
    res.headers.set("Cache-Control", "no-store");
    return res;
  };

  /**
   * Pass the request on. `fresh`: a token was just issued, so server code gets
   * it now. `dead`: the hub ended this session, so server code must not see
   * the old token at all, even if it has seconds left on it.
   *
   * The launcher's list travels with the token, by the same route and on the
   * same request: a renewal that brought a new list hands it to server code
   * now, not on the next page load.
   */
  function pass(
    req: NextRequest,
    change?: { token: string; handle: string; launcherApps: string[] | null } | "dead",
    grace = false,
  ) {
    const headers = new Headers(req.headers);
    headers.delete(GRACE_HEADER); // never trust one a browser sent
    if (grace) headers.set(GRACE_HEADER, "1");
    if (change) {
      // Server code reads cookies from the REQUEST, not from this response.
      const jar = new Map(req.cookies.getAll().map((c) => [c.name, c.value]));
      if (change === "dead") {
        jar.delete(names.token);
        jar.delete(names.handle);
        jar.delete(names.apps);
      } else {
        jar.set(names.token, change.token);
        jar.set(names.handle, change.handle);
        if (change.launcherApps) jar.set(names.apps, encodeLauncherApps(change.launcherApps));
        else jar.delete(names.apps);
      }
      const value = [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
      if (value) headers.set("cookie", value);
      else headers.delete("cookie");
    }
    const res = NextResponse.next({ request: { headers } });
    if (change === "dead") return clearOwn(res);
    if (change) {
      res.cookies.set(names.token, change.token, cookie(COOKIE_MAX_AGE_SECONDS));
      res.cookies.set(names.handle, change.handle, cookie(COOKIE_MAX_AGE_SECONDS));
      setLauncherApps(res, change.launcherApps);
    }
    return res;
  }

  async function startSignIn(req: NextRequest, markTried: boolean, sendBackTo?: string) {
    const state = randomValue(24);
    const verifier = randomValue(32);
    const returnTo = sendBackTo ?? req.nextUrl.pathname + req.nextUrl.search;
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
    /**
     * `mayRestart` is true only when the hub could not answer. The hub spends
     * nothing on that answer, so the sign-in is still there to be had; a
     * refusal (invalid, no_access), a state that does not match, or a token
     * this app would not accept are all answers, and are never retried.
     */
    const failed = async (why: string, mayRestart = false) => {
      log(`sign-in not completed: ${why}`);
      // `both`: the shared cookie carries on; the `tried` cookie stops a loop.
      if (o.mode === "both") return back(pending?.r ?? "/");
      // `own`: nothing to fall back on, so send the person through sign-in
      // once more, to the page they were going to. The code from this callback
      // is NOT used again: it may or may not have been spent, and the callback
      // must stay quick, so this starts a fresh sign-in. The marker makes a
      // second restart impossible while the first one is still good.
      if (mayRestart && req.method === "GET" && !req.cookies.has(names.restarted)) {
        const res = await startSignIn(req, false, pending?.r ?? "/");
        res.cookies.set(names.restarted, "1", cookie(STATE_TTL_SECONDS));
        return res;
      }
      const res = noStore(new NextResponse("Sign-in could not be completed. Go back and try again.", { status: 401 }));
      res.cookies.set(names.state, "", cookie(0));
      res.cookies.set(names.restarted, "", cookie(0));
      return res;
    };
    if (!pending || !code || !state || state !== pending.s) return failed("state");
    const granted = await hub.exchange(code, pending.v);
    if (!granted.ok) return failed(granted.reason, granted.reason === "unreachable");
    // Never store what this app would not itself accept.
    if ((await hub.check(granted.token)).state !== "valid") return failed("token");
    const res = back(pending.r);
    res.cookies.set(names.token, granted.token, cookie(COOKIE_MAX_AGE_SECONDS));
    res.cookies.set(names.handle, granted.handle, cookie(COOKIE_MAX_AGE_SECONDS));
    setLauncherApps(res, granted.launcherApps);
    res.cookies.set(names.tried, "", cookie(0));
    res.cookies.set(names.restarted, "", cookie(0));
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
      // The hub ended the app's own session. Signed in the old way as well:
      // the shared cookie carries on, and the dead token is hidden from server
      // code. Otherwise the person is signed out: the same as `own` below.
      if (ctx.legacySignedIn === true) return pass(req, "dead");
    }
    if (req.method !== "GET") return clearOwn(noStore(new NextResponse("Signed out", { status: 401 })));
    return clearOwn(await startSignIn(req, false));
  };
}
