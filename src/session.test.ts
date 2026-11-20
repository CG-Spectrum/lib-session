import { SignJWT, exportJWK, generateKeyPair } from "jose";
import { NextRequest } from "next/server";
import { beforeEach, describe, expect, it } from "vitest";
import {
  GRACE_HEADER, LAUNCHER_APPS_MAX_BYTES, LAUNCHER_APPS_MAX_COUNT, cookieNames, encodeLauncherApps, isPageNavigation,
  launcherAppsFrom, originAllowed, originGuardMode, parseLauncherApps, readPending, safeReturnTo, sessionMode,
} from "./core";
import { createHub } from "./hub";
import { createSessionMiddleware, type AppSessionOptions } from "./middleware";
import { readAppSession, readLauncherApps } from "./server";

const HUB = "https://auth.cgspectrum.com";
const APP = "https://console.cgspectrum.com";
const names = cookieNames(true);
const key = await generateKeyPair("ES256", { extractable: true });
const other = await generateKeyPair("ES256", { extractable: true });
const jwks = { keys: [{ ...(await exportJWK(key.publicKey)), kid: "k1", alg: "ES256", use: "sig" }] };

let clock = Date.parse("2026-11-19T00:00:00Z");
const secs = () => Math.floor(clock / 1000);

async function mint(over: Record<string, unknown> = {}, opts: { aud?: string; iss?: string; ttl?: number; signer?: CryptoKey } = {}) {
  return new SignJWT({ sid: "s1", email: "A@cgspectrum.com", name: "A", gsub: "g1", lprov: "workos", kind: "staff", role: "staff", departments: [], appRole: null, ...over })
    .setProtectedHeader({ alg: "ES256", kid: "k1" })
    .setIssuer(opts.iss ?? HUB).setAudience(opts.aud ?? "console").setIssuedAt(secs()).setExpirationTime(secs() + (opts.ttl ?? 900))
    .sign(opts.signer ?? key.privateKey);
}

// A stand-in hub: what /token answers is set per test.
let hubState: { jwks: number; token: () => Promise<Response> | Response; calls: { url: string; body?: Record<string, string> }[] };
const fakeFetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
  const url = String(input instanceof Request ? input.url : input);
  hubState.calls.push({ url, body: init?.body ? JSON.parse(String(init.body)) : undefined });
  if (url.endsWith("/.well-known/jwks.json")) {
    if (hubState.jwks !== 200) return new Response("no", { status: hubState.jwks });
    return new Response(JSON.stringify(jwks), { status: 200, headers: { "content-type": "application/json" } });
  }
  if (url.endsWith("/token")) return hubState.token();
  return new Response("?", { status: 404 });
}) as typeof fetch;
const grant = async (over?: Parameters<typeof mint>[0], opts?: Parameters<typeof mint>[1]) =>
  new Response(JSON.stringify({ token: await mint(over, opts), handle: "h-next", expires_in: 900 }), { status: 200 });
const down = () => { throw new Error("network"); };
/** The hub has nothing to give right now: it has spent nothing. */
const busy = (retryAfter?: string) =>
  new Response(JSON.stringify({ error: "busy" }), {
    status: 503, headers: retryAfter === undefined ? {} : { "retry-after": retryAfter },
  });
const tokenCalls = () => hubState.calls.filter((c) => c.url.endsWith("/token")).length;

function setup(over: Partial<AppSessionOptions> = {}) {
  const o: AppSessionOptions = {
    app: "console", hubUrl: HUB, mode: "own", originGuard: "enforce", secure: true,
    legacyCookieNames: ["__Secure-authjs.session-token"], fetch: fakeFetch, now: () => clock, log: () => {}, ...over,
  };
  const hub = createHub(o);
  return { hub, handle: createSessionMiddleware(o, hub) };
}
function request(path: string, init: { method?: string; cookies?: Record<string, string>; headers?: Record<string, string> } = {}) {
  const headers = new Headers({ "sec-fetch-dest": "document", accept: "text/html", ...init.headers });
  const jar = Object.entries(init.cookies ?? {}).map(([k, v]) => `${k}=${v}`).join("; ");
  if (jar) headers.set("cookie", jar);
  return new NextRequest(new URL(path, APP), { method: init.method ?? "GET", headers });
}
const setCookie = (res: Response, name: string) =>
  res.headers.getSetCookie().find((c) => c.startsWith(`${name}=`));
const forwarded = (res: Response) => res.headers.get("x-middleware-request-cookie") ?? "";

beforeEach(() => {
  clock = Date.parse("2026-11-19T00:00:00Z");
  hubState = { jwks: 200, token: () => new Response("{}", { status: 401 }), calls: [] };
});

describe("settings", () => {
  it("a typo in the mode changes nothing", () => {
    expect(sessionMode(undefined)).toBe("shared");
    expect(sessionMode("Both")).toBe("both");
    expect(sessionMode("own")).toBe("own");
    for (const v of ["", "on", "true", "owned", "shard"]) expect(sessionMode(v)).toBe("shared");
  });
  it("the origin guard is off while shared and on otherwise, unless set", () => {
    expect(originGuardMode(undefined, "shared")).toBe("off");
    expect(originGuardMode(undefined, "both")).toBe("enforce");
    expect(originGuardMode("report", "own")).toBe("report");
    expect(originGuardMode("nonsense", "own")).toBe("enforce");
  });
  it("cookies are host-only in production", () => expect(names.token).toBe("__Host-cgsi.session"));
});

describe("where a person is sent back to", () => {
  it("only ever a path on this app", () => {
    expect(safeReturnTo("/people?q=a")).toBe("/people?q=a");
    for (const v of ["//evil.test", "https://evil.test", "/\\evil.test", "people", "/a\nb", undefined, 3]) expect(safeReturnTo(v)).toBe("/");
    expect(readPending(JSON.stringify({ s: "s", v: "v", r: "//evil.test" }))?.r).toBe("/");
    expect(readPending("not json")).toBeNull();
  });
});

describe("writes must come from the app's own pages", () => {
  const host = "console.cgspectrum.com";
  const from = (origin: string | null, secFetchSite: string | null = null, method = "POST") =>
    originAllowed({ method, origin, secFetchSite, host });
  it("reads are never blocked", () => expect(from("https://www.cgspectrum.com", "same-site", "GET")).toBe(true));
  it("the app's own pages may write", () => expect(from(`https://${host}`, "same-origin")).toBe(true));
  it("sibling hosts may not, though they are the same SITE", () => {
    expect(from("https://www.cgspectrum.com", "same-site")).toBe(false);
    expect(from("https://learn.cgspectrum.com", "same-site")).toBe(false);
  });
  it("another site, a look-alike host and a sandboxed page may not", () => {
    expect(from("https://evil.test", "cross-site")).toBe(false);
    expect(from(`https://${host}.evil.test`)).toBe(false);
    expect(from("null")).toBe(false);
  });
  it("no Origin: same-origin or not a browser is fine; same-site or cross-site is not", () => {
    expect(from(null, null)).toBe(true);
    expect(from(null, "same-origin")).toBe(true);
    expect(from(null, "same-site")).toBe(false);
    expect(from(null, "cross-site")).toBe(false);
  });
  it("a listed sibling app may call", () =>
    expect(originAllowed({ method: "POST", origin: "https://home.cgspectrum.com", secFetchSite: "same-site", host, allowed: ["https://home.cgspectrum.com"] })).toBe(true));
});

describe("a page navigation", () => {
  const h = (o: Record<string, string>) => new Headers(o);
  it("is a browser asking for a document, not a fetch or a prefetch", () => {
    expect(isPageNavigation("GET", h({ "sec-fetch-dest": "document" }))).toBe(true);
    expect(isPageNavigation("GET", h({ "sec-fetch-dest": "empty", accept: "text/html" }))).toBe(false);
    expect(isPageNavigation("GET", h({ "sec-fetch-dest": "document", rsc: "1" }))).toBe(false);
    expect(isPageNavigation("GET", h({ "sec-fetch-dest": "document", "next-router-prefetch": "1" }))).toBe(false);
    expect(isPageNavigation("POST", h({ "sec-fetch-dest": "document" }))).toBe(false);
  });
});

describe("checking a token", () => {
  it("accepts one the hub signed for this app", async () => {
    const c = await setup().hub.check(await mint());
    expect(c.state).toBe("valid");
    if (c.state === "valid") expect(c.session).toMatchObject({ email: "a@cgspectrum.com", subject: "g1", loginProvider: "workos", kind: "staff" });
  });
  it("refuses a token for ANOTHER app, from another hub, or signed by another key", async () => {
    const { hub } = setup();
    expect((await hub.check(await mint({}, { aud: "home" }))).state).toBe("invalid");
    expect((await hub.check(await mint({}, { iss: "https://auth.staging.cgspectrum.com" }))).state).toBe("invalid");
    expect((await hub.check(await mint({}, { signer: other.privateKey }))).state).toBe("invalid");
  });
  it("refuses an unsigned token and a tampered one", async () => {
    const { hub } = setup();
    const good = await mint();
    const [h, p] = good.split(".");
    const none = `${btoa(JSON.stringify({ alg: "none" })).replace(/=+$/, "")}.${p}.`;
    expect((await hub.check(none)).state).toBe("invalid");
    const swapped = JSON.parse(atob(p.replace(/-/g, "+").replace(/_/g, "/")));
    swapped.role = "admin";
    const p2 = btoa(JSON.stringify(swapped)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    expect((await hub.check(`${h}.${p2}.${good.split(".")[2]}`)).state).toBe("invalid");
  });
  it("an old token is 'expired', and only if the hub really signed it", async () => {
    const { hub } = setup();
    const mine = await mint();
    const forged = await mint({}, { signer: other.privateKey });
    clock += 20 * 60 * 1000;
    const c = await hub.check(mine);
    expect(c.state).toBe("expired");
    if (c.state === "expired") expect(c.expiredForSeconds).toBe(300);
    expect((await hub.check(forged)).state).toBe("invalid");
  });
  it("refuses a token missing the login", async () =>
    expect((await setup().hub.check(await mint({ gsub: "" }))).state).toBe("invalid"));
});

describe("mode shared", () => {
  it("does nothing at all", async () => {
    const { handle } = setup({ mode: "shared", originGuard: "off" });
    expect(await handle(request("/people"))).toBeNull();
    expect(await handle(request("/session/callback?code=x&state=y"))).toBeNull();
    expect(hubState.calls).toHaveLength(0);
  });
});

describe("mode own", () => {
  it("no session: sends the person to the hub and remembers where they were going", async () => {
    const res = (await setup().handle(request("/people?q=a")))!;
    const to = new URL(res.headers.get("location")!);
    expect(to.origin + to.pathname).toBe(`${HUB}/authorize`);
    expect(to.searchParams.get("app")).toBe("console");
    expect(to.searchParams.get("challenge")).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const state = setCookie(res, names.state)!;
    expect(state).toContain("HttpOnly");
    expect(state).toContain("Secure");
    expect(state).not.toContain("Domain=");
    const pending = readPending(decodeURIComponent(state.split(";")[0].split("=").slice(1).join("=")))!;
    expect(pending.r).toBe("/people?q=a");
    expect(pending.s).toBe(to.searchParams.get("state"));
    // The verifier stays in the cookie; only its hash goes to the hub.
    expect(res.headers.get("location")).not.toContain(pending.v);
  });
  it("no session on a write: 401, never a redirect", async () =>
    expect((await setup().handle(request("/x", { method: "POST", headers: { origin: APP } })))!.status).toBe(401));
  it("a good token passes without calling the hub's token route", async () => {
    const res = (await setup().handle(request("/", { cookies: { [names.token]: await mint(), [names.handle]: "h1" } })))!;
    expect(res.headers.get("x-middleware-next")).toBe("1");
    expect(hubState.calls.filter((c) => c.url.endsWith("/token"))).toHaveLength(0);
  });
  it("a public path is left alone", async () =>
    expect(await setup({ publicPaths: ["/api/cron/"] }).handle(request("/api/cron/nightly"))).toBeNull());
});

describe("finishing a sign-in", () => {
  const pending = JSON.stringify({ s: "state-1", v: "verifier-1", r: "/people" });
  it("swaps the code for a token, sets two host-only cookies and goes back", async () => {
    hubState.token = () => grant();
    const res = (await setup().handle(request("/session/callback?code=c1&state=state-1", { cookies: { [names.state]: pending } })))!;
    expect(res.headers.get("location")).toBe(`${APP}/people`);
    for (const n of [names.token, names.handle]) {
      const c = setCookie(res, n)!;
      expect(c).toContain("HttpOnly");
      expect(c).toContain("Secure");
      expect(c).toContain("Path=/");
      expect(c).not.toContain("Domain=");
    }
    const sent = hubState.calls.find((c) => c.url.endsWith("/token"))!.body;
    expect(sent).toEqual({ app: "console", grant: "code", code: "c1", verifier: "verifier-1" });
  });
  it("a state that does not match is refused and the hub is never called", async () => {
    const res = (await setup().handle(request("/session/callback?code=c1&state=WRONG", { cookies: { [names.state]: pending } })))!;
    expect(res.status).toBe(401);
    expect(hubState.calls).toHaveLength(0);
  });
  it("no pending sign-in (a link somebody was sent): refused", async () =>
    expect((await setup().handle(request("/session/callback?code=c1&state=state-1")))!.status).toBe(401));
  it("a token for another app is never stored", async () => {
    hubState.token = () => grant({}, { aud: "home" });
    const res = (await setup().handle(request("/session/callback?code=c1&state=state-1", { cookies: { [names.state]: pending } })))!;
    expect(res.status).toBe(401);
    expect(setCookie(res, names.token)).toBeUndefined();
  });
  it("mode both: a failure goes back to the page on the shared cookie, not an error", async () => {
    const res = (await setup({ mode: "both" }).handle(request("/session/callback?code=c1&state=state-1", { cookies: { [names.state]: pending } })))!;
    expect(res.headers.get("location")).toBe(`${APP}/people`);
    expect(setCookie(res, names.token)).toBeUndefined();
  });
});

describe("renewal", () => {
  it("renews in the last minute and hands the NEW token to the same request", async () => {
    const old = await mint({}, { ttl: 30 });
    hubState.token = () => grant({ sid: "s1" });
    const res = (await setup().handle(request("/", { cookies: { [names.token]: old, [names.handle]: "h1", other: "x" } })))!;
    expect(hubState.calls.find((c) => c.url.endsWith("/token"))!.body).toEqual({ app: "console", grant: "renew", handle: "h1" });
    expect(setCookie(res, names.handle)).toContain("h-next");
    expect(forwarded(res)).toContain(`${names.handle}=h-next`);
    expect(forwarded(res)).not.toContain(old);
    expect(forwarded(res)).toContain("other=x");
  });
  it("renews an expired token on a write too: no redirect, the request goes through", async () => {
    const old = await mint();
    clock += 16 * 60 * 1000;
    hubState.token = () => grant();
    const res = (await setup().handle(request("/save", { method: "POST", headers: { origin: APP }, cookies: { [names.token]: old, [names.handle]: "h1" } })))!;
    expect(res.headers.get("x-middleware-next")).toBe("1");
  });
  it("the hub says the session is over: cookies cleared, back to the hub", async () => {
    const old = await mint();
    clock += 16 * 60 * 1000;
    const res = (await setup().handle(request("/", { cookies: { [names.token]: old, [names.handle]: "h1" } })))!;
    expect(new URL(res.headers.get("location")!).pathname).toBe("/authorize");
    expect(setCookie(res, names.token)).toContain("Max-Age=0");
  });
  it("the hub says no access: refused in every mode, never the shared cookie", async () => {
    const old = await mint({}, { ttl: 30 });
    hubState.token = () => new Response("{}", { status: 403 });
    for (const mode of ["own", "both"] as const) {
      const res = (await setup({ mode }).handle(request("/", { cookies: { [names.token]: old, [names.handle]: "h1" } }), { legacySignedIn: true }))!;
      expect(res.headers.get("location")).toBe(`${HUB}/no-access?app=console`);
      expect(setCookie(res, names.token)).toContain("Max-Age=0");
    }
  });
});

describe("the hub cannot be reached", () => {
  it("an expired token is honoured for up to an hour, and marked", async () => {
    const old = await mint();
    const { handle, hub } = setup();
    await hub.check(old); // the public key is already cached, as it would be
    hubState.token = down;
    clock += 50 * 60 * 1000;
    const res = (await handle(request("/", { cookies: { [names.token]: old, [names.handle]: "h1" } })))!;
    expect(res.headers.get("x-middleware-next")).toBe("1");
    expect(res.headers.get(`x-middleware-request-${GRACE_HEADER}`)).toBe("1");
  });
  it("after an hour it is not", async () => {
    const old = await mint();
    const { handle, hub } = setup();
    await hub.check(old);
    hubState.token = down;
    clock += (15 + 61) * 60 * 1000;
    const res = (await handle(request("/", { cookies: { [names.token]: old, [names.handle]: "h1" } })))!;
    expect(new URL(res.headers.get("location")!).pathname).toBe("/authorize");
  });
  it("a hub error (500) counts as unreachable; a refusal (401) never does", async () => {
    const old = await mint();
    const { handle, hub } = setup();
    await hub.check(old);
    clock += 20 * 60 * 1000;
    hubState.token = () => new Response("boom", { status: 500 });
    expect((await handle(request("/", { cookies: { [names.token]: old, [names.handle]: "h1" } })))!.headers.get("x-middleware-next")).toBe("1");
    clock += 1100; // past the moment the hub is left alone for after failing to answer
    hubState.token = () => new Response("{}", { status: 401 });
    expect((await handle(request("/", { cookies: { [names.token]: old, [names.handle]: "h1" } })))!.headers.get("location")).toContain("/authorize");
  });
  it("a grace marker sent by a browser is removed", async () => {
    const res = (await setup().handle(request("/", { headers: { [GRACE_HEADER]: "1" }, cookies: { [names.token]: await mint(), [names.handle]: "h1" } })))!;
    // This header lists every request header passed on; the marker is not among them.
    expect(res.headers.get("x-middleware-override-headers")).toBe("accept,cookie,sec-fetch-dest");
    expect(res.headers.get(`x-middleware-request-${GRACE_HEADER}`)).toBeNull();
  });
});

describe("the grace period", () => {
  const graced = (res: Response) => res.headers.get(`x-middleware-request-${GRACE_HEADER}`);

  it("is set only when a renewal in this same request could not reach the hub", async () => {
    const old = await mint();
    clock += 20 * 60 * 1000; // five minutes past its time
    const signedIn = { [names.token]: old, [names.handle]: "h1" };

    hubState.token = () => new Response("{}", { status: 401 });
    const refused = (await setup().handle(request("/", { cookies: signedIn })))!;
    expect(graced(refused)).toBeNull();
    expect(refused.headers.get("location")).toContain("/authorize");

    hubState.token = () => new Response("{}", { status: 403 });
    const noAccess = (await setup().handle(request("/", { cookies: signedIn })))!;
    expect(graced(noAccess)).toBeNull();
    expect(noAccess.headers.get("location")).toBe(`${HUB}/no-access?app=console`);

    hubState.token = () => busy("1");
    const noHandle = (await setup().handle(request("/", { cookies: { [names.token]: old } })))!;
    expect(graced(noHandle)).toBeNull();
    expect(noHandle.headers.get("location")).toContain("/authorize");
    expect(tokenCalls()).toBe(2); // with no handle there is nothing to attempt

    const unreachable = (await setup().handle(request("/", { cookies: signedIn })))!;
    expect(unreachable.headers.get("x-middleware-next")).toBe("1");
    expect(graced(unreachable)).toBe("1");

    // A token with time left on it, renewed early, hub unreachable: passed on,
    // and not marked, because it has not expired.
    const early = (await setup().handle(request("/", { cookies: { [names.token]: await mint({}, { ttl: 30 }), [names.handle]: "h1" } })))!;
    expect(early.headers.get("x-middleware-next")).toBe("1");
    expect(graced(early)).toBeNull();
  });

  it("while the hub is left alone an expired token is carried unasked, and the first call after it ends the session", async () => {
    const old = await mint();
    clock += 20 * 60 * 1000;
    const signedIn = { [names.token]: old, [names.handle]: "h1" };
    hubState.token = () => busy("5");
    const { handle } = setup();

    const asked = (await handle(request("/", { cookies: signedIn })))!;
    expect(tokenCalls()).toBe(1);
    expect(graced(asked)).toBe("1");

    // Inside the pause nothing is asked, so a refusal the hub would give now
    // cannot arrive, and the person is carried.
    hubState.token = () => new Response("{}", { status: 401 });
    clock += 4000;
    const carried = (await handle(request("/", { cookies: signedIn })))!;
    expect(tokenCalls()).toBe(1);
    expect(graced(carried)).toBe("1");

    // The first call made after the pause gets the real answer, at once.
    clock += 1100;
    const ended = (await handle(request("/", { cookies: signedIn })))!;
    expect(tokenCalls()).toBe(2);
    expect(graced(ended)).toBeNull();
    expect(ended.headers.get("location")).toContain("/authorize");
    expect(setCookie(ended, names.token)).toContain("Max-Age=0");
  });
});

describe("mode both", () => {
  const legacy = { "__Secure-authjs.session-token": "legacy" };
  it("not signed in at all: not mine (the app's old redirect runs)", async () =>
    expect(await setup({ mode: "both" }).handle(request("/"), { legacySignedIn: false })).toBeNull());
  it("signed in the old way, on a page: moves the person onto their own session, once", async () => {
    const res = (await setup({ mode: "both" }).handle(request("/people", { cookies: legacy }), { legacySignedIn: true }))!;
    expect(new URL(res.headers.get("location")!).pathname).toBe("/authorize");
    expect(setCookie(res, names.tried)).toContain("Max-Age=300");
  });
  it("already tried recently: stays on the shared cookie", async () =>
    expect(await setup({ mode: "both" }).handle(request("/people", { cookies: { ...legacy, [names.tried]: "1" } }), { legacySignedIn: true })).toBeNull());
  it("the hub does not offer per-app sessions (404): stays on the shared cookie", async () => {
    hubState.jwks = 404;
    expect(await setup({ mode: "both" }).handle(request("/people", { cookies: legacy }), { legacySignedIn: true })).toBeNull();
  });
  it("a background fetch or a write is never interrupted", async () => {
    const { handle } = setup({ mode: "both" });
    expect(await handle(request("/people", { cookies: legacy, headers: { "sec-fetch-dest": "empty" } }), { legacySignedIn: true })).toBeNull();
    expect(await handle(request("/save", { method: "POST", cookies: legacy, headers: { origin: APP } }), { legacySignedIn: true })).toBeNull();
  });
  it("its own session, when there is one, is what passes", async () => {
    const res = (await setup({ mode: "both" }).handle(request("/", { cookies: { ...legacy, [names.token]: await mint(), [names.handle]: "h1" } }), { legacySignedIn: true }))!;
    expect(res.headers.get("x-middleware-next")).toBe("1");
  });
});

describe("mode both, when the hub has ended the app's own session", () => {
  const legacy = { "__Secure-authjs.session-token": "legacy" };
  // The token still has 30 seconds on it; the hub refuses to renew (401).
  const dying = async () => ({ [names.token]: await mint({}, { ttl: 30 }), [names.handle]: "h1" });
  it("still signed in the old way: carries on, and server code never sees the dead token", async () => {
    const cookies = { ...legacy, ...(await dying()), other: "x" };
    const res = (await setup({ mode: "both" }).handle(request("/people", { cookies, headers: { "sec-fetch-dest": "empty" } }), { legacySignedIn: true }))!;
    expect(res.headers.get("x-middleware-next")).toBe("1");
    expect(forwarded(res)).not.toContain(names.token);
    expect(forwarded(res)).not.toContain(names.handle);
    expect(forwarded(res)).toContain("__Secure-authjs.session-token=legacy");
    expect(forwarded(res)).toContain("other=x");
    expect(setCookie(res, names.token)).toContain("Max-Age=0");
  });
  it("NOT signed in the old way either: signed out, never passed through on a token's last seconds", async () => {
    const page = (await setup({ mode: "both" }).handle(request("/people", { cookies: await dying() }), { legacySignedIn: false }))!;
    expect(new URL(page.headers.get("location")!).pathname).toBe("/authorize");
    expect(setCookie(page, names.token)).toContain("Max-Age=0");
    const write = (await setup({ mode: "both" }).handle(request("/save", { method: "POST", headers: { origin: APP }, cookies: await dying() }), { legacySignedIn: false }))!;
    expect(write.status).toBe(401);
    const background = (await setup({ mode: "both" }).handle(request("/people", { cookies: await dying(), headers: { "sec-fetch-dest": "empty" } }), { legacySignedIn: false }))!;
    expect(background.headers.get("x-middleware-next")).toBeNull();
  });
  it("a forged token with no shared cookie is signed out too", async () => {
    const res = (await setup({ mode: "both" }).handle(request("/people", { cookies: { [names.token]: "forged" } }), { legacySignedIn: false }))!;
    expect(new URL(res.headers.get("location")!).pathname).toBe("/authorize");
  });
});

describe("the origin guard in the middleware", () => {
  const signedIn = async () => ({ [names.token]: await mint(), [names.handle]: "h1" });
  it("refuses a signed-in write from a sibling host", async () => {
    const res = (await setup().handle(request("/save", { method: "POST", headers: { origin: "https://www.cgspectrum.com" }, cookies: await signedIn() })))!;
    expect(res.status).toBe(403);
  });
  it("also protects a person signed in the OLD way", async () => {
    const res = (await setup({ mode: "both" }).handle(request("/save", { method: "POST", headers: { origin: "https://learn.cgspectrum.com" }, cookies: { "__Secure-authjs.session-token": "x" } }), { legacySignedIn: true }))!;
    expect(res.status).toBe(403);
  });
  it("report mode logs and lets it through", async () => {
    const seen: string[] = [];
    const res = (await setup({ originGuard: "report", log: (m) => seen.push(m) }).handle(request("/save", { method: "POST", headers: { origin: "https://www.cgspectrum.com" }, cookies: await signedIn() })))!;
    expect(res.headers.get("x-middleware-next")).toBe("1");
    expect(seen.join()).toContain("report only");
  });
  it("leaves a machine caller with no session alone (a webhook)", async () => {
    const res = await setup({ publicPaths: ["/api/hook"] }).handle(request("/api/hook", { method: "POST", headers: { origin: "https://hooks.example.com" } }));
    expect(res).toBeNull();
  });
});

describe("signing out", () => {
  it("clears this app's cookies and goes to the hub's sign-out", async () => {
    const res = (await setup().handle(request("/session/signout", { cookies: { [names.token]: await mint() } })))!;
    expect(res.headers.get("location")).toBe(`${HUB}/signout?callbackUrl=${encodeURIComponent(APP)}`);
    expect(setCookie(res, names.token)).toContain("Max-Age=0");
    expect(setCookie(res, names.handle)).toContain("Max-Age=0");
  });
});

describe("signing out, with a page to come back to", () => {
  const after = (res: Response) => new URL(res.headers.get("location")!).searchParams.get("callbackUrl");
  it("comes back to a page on this app", async () =>
    expect(after((await setup().handle(request(`/session/signout?callbackUrl=${encodeURIComponent(`${APP}/people`)}`)))!)).toBe(`${APP}/people`));
  it("never to another site", async () =>
    expect(after((await setup().handle(request(`/session/signout?callbackUrl=${encodeURIComponent("https://evil.test/x")}`)))!)).toBe(APP));
  it("works for a person still on the shared cookie (mode both)", async () =>
    expect((await setup({ mode: "both" }).handle(request("/session/signout"), { legacySignedIn: true }))!.headers.get("location")).toContain(`${HUB}/signout`));
});

describe("a sign-in the hub could not answer", () => {
  const pending = JSON.stringify({ s: "state-1", v: "verifier-1", r: "/people" });
  const callback = (cookies: Record<string, string>) => request("/session/callback?code=c1&state=state-1", { cookies });

  it("own: starts a fresh sign-in once, back to the page the person wanted", async () => {
    hubState.token = () => busy("1");
    const res = (await setup().handle(callback({ [names.state]: pending })))!;
    const to = new URL(res.headers.get("location")!);
    expect(to.origin + to.pathname).toBe(`${HUB}/authorize`);
    const started = readPending(decodeURIComponent(setCookie(res, names.state)!.split(";")[0].split("=").slice(1).join("=")))!;
    expect(started.r).toBe("/people");
    expect(started.s).toBe(to.searchParams.get("state"));
    expect(started.s).not.toBe("state-1"); // a fresh sign-in, not the old one again
    const marker = setCookie(res, names.restarted)!;
    expect(marker).toContain("HttpOnly");
    expect(marker).toContain("Secure");
    expect(marker).not.toContain("Domain=");
    expect(marker).toContain("Max-Age=600");
    expect(tokenCalls()).toBe(1); // the code from this callback is never sent twice
  });

  it("own: a second failure shows the page, and clears the marker", async () => {
    hubState.token = () => busy("1");
    const res = (await setup().handle(callback({ [names.state]: pending, [names.restarted]: "1" })))!;
    expect(res.status).toBe(401);
    expect(await res.text()).toContain("Sign-in could not be completed");
    expect(res.headers.get("location")).toBeNull();
    expect(setCookie(res, names.restarted)).toContain("Max-Age=0");
  });

  it("own: a refusal, a state that does not match and a bad token are never restarted", async () => {
    for (const answer of [() => new Response("{}", { status: 401 }), () => new Response("{}", { status: 403 }), () => grant({}, { aud: "home" })]) {
      hubState.token = answer;
      const res = (await setup().handle(callback({ [names.state]: pending })))!;
      expect(res.status).toBe(401);
      expect(res.headers.get("location")).toBeNull();
      expect(setCookie(res, names.restarted)).toContain("Max-Age=0");
    }
    hubState.token = () => busy("1");
    const mismatch = (await setup().handle(request("/session/callback?code=c1&state=WRONG", { cookies: { [names.state]: pending } })))!;
    expect(mismatch.status).toBe(401);
    expect(tokenCalls()).toBe(3); // the mismatch never reached the hub
  });

  it("own: the marker is cleared when a sign-in succeeds", async () => {
    hubState.token = () => grant();
    const res = (await setup().handle(callback({ [names.state]: pending, [names.restarted]: "1" })))!;
    expect(res.headers.get("location")).toBe(`${APP}/people`);
    expect(setCookie(res, names.restarted)).toContain("Max-Age=0");
  });

  it("own: carrying the marker the first answer set cannot start a third attempt, so there is no loop", async () => {
    hubState.token = () => busy("1");
    const { handle } = setup();
    const first = (await handle(callback({ [names.state]: pending })))!;
    expect(first.headers.get("location")).toContain("/authorize");
    const carried = setCookie(first, names.restarted)!.split(";")[0].split("=").slice(1).join("=");
    const second = (await handle(callback({ [names.state]: pending, [names.restarted]: carried })))!;
    expect(second.status).toBe(401);
    const third = (await handle(callback({ [names.state]: pending, [names.restarted]: carried })))!;
    expect(third.status).toBe(401);
  });

  it("own: a hub that stays down cannot loop the browser, because the marker travels back with it", async () => {
    hubState.token = () => busy("1");
    const { handle } = setup();
    // A browser's cookie jar, filled from what each answer sets.
    const jar: Record<string, string> = {};
    const browserGoesTo = async (path: string) => {
      const res = (await handle(request(path, { cookies: { ...jar } })))!;
      for (const c of res.headers.getSetCookie()) {
        const [pair, ...attributes] = c.split(";");
        const at = pair.indexOf("=");
        if (attributes.some((a) => a.trim().toLowerCase() === "max-age=0")) delete jar[pair.slice(0, at)];
        else jar[pair.slice(0, at)] = decodeURIComponent(pair.slice(at + 1));
      }
      return res;
    };
    const comingBackFromTheHub = () =>
      `/session/callback?code=c1&state=${encodeURIComponent(readPending(jar[names.state])!.s)}`;

    const page = await browserGoesTo("/people");
    expect(page.headers.get("location")).toContain("/authorize");
    const firstTry = await browserGoesTo(comingBackFromTheHub());
    expect(firstTry.headers.get("location")).toContain("/authorize"); // one restart
    expect(jar[names.restarted]).toBe("1"); // the browser is carrying the marker
    expect(readPending(jar[names.state])!.r).toBe("/people");
    const secondTry = await browserGoesTo(comingBackFromTheHub());
    expect(secondTry.status).toBe(401);
    expect(secondTry.headers.get("location")).toBeNull(); // the page, not another round
    expect(jar[names.restarted]).toBeUndefined();
    expect(tokenCalls()).toBe(2); // two exchanges, never the same code twice
  });

  it("both is unchanged: back to the page on the shared cookie, and no restart", async () => {
    hubState.token = () => busy("1");
    const res = (await setup({ mode: "both" }).handle(callback({ [names.state]: pending })))!;
    expect(res.headers.get("location")).toBe(`${APP}/people`);
    expect(setCookie(res, names.restarted)).toBeUndefined();
    expect(setCookie(res, names.token)).toBeUndefined();
  });
});

describe("the hub says it is busy", () => {
  it("skips renewal calls for as long as the hub asked", async () => {
    hubState.token = () => busy("3");
    const { hub } = setup();
    expect((await hub.renew("h1")).ok).toBe(false);
    expect(tokenCalls()).toBe(1);
    expect(await hub.renew("h2")).toEqual({ ok: false, reason: "unreachable" });
    expect(tokenCalls()).toBe(1);
    clock += 2900;
    await hub.renew("h3");
    expect(tokenCalls()).toBe(1);
    clock += 200;
    await hub.renew("h4");
    expect(tokenCalls()).toBe(2);
  });

  it("clamps a silly Retry-After to between one and five seconds", async () => {
    hubState.token = () => busy("900");
    const long = setup().hub;
    await long.renew("h1");
    clock += 4900;
    await long.renew("h2");
    expect(tokenCalls()).toBe(1);
    clock += 200;
    await long.renew("h3");
    expect(tokenCalls()).toBe(2);

    hubState.token = () => busy("0");
    const short = setup().hub;
    await short.renew("a1");
    expect(tokenCalls()).toBe(3);
    clock += 500;
    await short.renew("a2");
    expect(tokenCalls()).toBe(3);
    clock += 600;
    await short.renew("a3");
    expect(tokenCalls()).toBe(4);
  });

  it("waits a second when the Retry-After is missing or not whole seconds, and when there is no answer at all", async () => {
    const answers: (typeof hubState.token)[] = [
      () => busy(), () => busy("soon"), () => busy("Wed, 19 Nov 2026 00:00:30 GMT"), down,
    ];
    for (const answer of answers) {
      hubState.calls = [];
      hubState.token = answer;
      const { hub } = setup();
      await hub.renew("h1");
      clock += 900;
      await hub.renew("h2");
      expect(tokenCalls()).toBe(1);
      clock += 200;
      await hub.renew("h3");
      expect(tokenCalls()).toBe(2);
    }
  });

  it("never holds off a person finishing a sign-in", async () => {
    hubState.token = () => busy("5");
    const { hub } = setup();
    await hub.renew("h1");
    expect(tokenCalls()).toBe(1);
    expect((await hub.exchange("c1", "verifier-1")).ok).toBe(false);
    expect(tokenCalls()).toBe(2);
    expect(hubState.calls.at(-1)!.body).toEqual({ app: "console", grant: "code", code: "c1", verifier: "verifier-1" });
  });
});

describe("renewing once for a handle", () => {
  it("requests arriving together with one handle make a single call and share its answer", async () => {
    hubState.token = () => grant();
    const { hub } = setup();
    const answers = await Promise.all([1, 2, 3, 4, 5].map(() => hub.renew("h1")));
    expect(tokenCalls()).toBe(1);
    expect(answers[0].ok).toBe(true);
    for (const a of answers) expect(a).toBe(answers[0]);
  });

  it("another handle gets its own call", async () => {
    hubState.token = () => grant();
    const { hub } = setup();
    const [a, b] = await Promise.all([hub.renew("h1"), hub.renew("h2")]);
    expect(tokenCalls()).toBe(2);
    expect(a).not.toBe(b);
    expect(hubState.calls.filter((c) => c.url.endsWith("/token")).map((c) => c.body?.handle).sort()).toEqual(["h1", "h2"]);
  });

  it("the shared answer lasts a few seconds and then goes", async () => {
    hubState.token = () => grant();
    const { hub } = setup();
    const first = await hub.renew("h1");
    clock += 2000;
    expect(await hub.renew("h1")).toBe(first);
    expect(tokenCalls()).toBe(1);
    clock += 1100;
    expect(await hub.renew("h1")).not.toBe(first);
    expect(tokenCalls()).toBe(2);
  });

  it("only so many handles are held at once", async () => {
    hubState.token = () => grant();
    const { hub } = setup();
    for (let i = 0; i < 120; i++) await hub.renew(`h${i}`);
    expect(tokenCalls()).toBe(120);
    await hub.renew("h119"); // still held: shared, no call
    expect(tokenCalls()).toBe(120);
    await hub.renew("h0"); // dropped long ago to keep the map small: a call of its own
    expect(tokenCalls()).toBe(121);
  });

  it("logs a reason only: never a handle, a token or a code", async () => {
    const seen: string[] = [];
    hubState.token = () => busy("1");
    const { handle } = setup({ log: (m) => seen.push(m) });
    const old = await mint({}, { ttl: 30 });
    await handle(request("/", { cookies: { [names.token]: old, [names.handle]: "handle-abc" } }));
    await handle(request("/session/callback?code=code-abc&state=state-1", {
      cookies: { [names.state]: JSON.stringify({ s: "state-1", v: "verifier-abc", r: "/people" }) },
    }));
    expect(seen.length).toBeGreaterThan(0);
    for (const line of seen) {
      for (const secret of ["handle-abc", "code-abc", "verifier-abc", old]) expect(line).not.toContain(secret);
    }
  });
});

describe("server code reading the session", () => {
  const jar = (token?: string) => ({ get: (n: string) => (n === names.token && token ? { value: token } : undefined) });
  it("a good token is the person; no token is nobody", async () => {
    const { hub } = setup();
    expect((await readAppSession(hub, true, jar(await mint())))?.email).toBe("a@cgspectrum.com");
    expect(await readAppSession(hub, true, jar())).toBeNull();
  });
  it("an expired token is nobody, unless the middleware marked the hub unreachable", async () => {
    const { hub } = setup();
    const old = await mint();
    await hub.check(old);
    clock += 30 * 60 * 1000;
    expect(await readAppSession(hub, true, jar(old))).toBeNull();
    expect((await readAppSession(hub, true, jar(old), new Headers({ [GRACE_HEADER]: "1" })))?.sid).toBe("s1");
    clock += 60 * 60 * 1000;
    expect(await readAppSession(hub, true, jar(old), new Headers({ [GRACE_HEADER]: "1" }))).toBeNull();
  });
  it("the marker never rescues a token the hub did not sign", async () => {
    const { hub } = setup();
    const forged = await mint({ role: "admin" }, { signer: other.privateKey });
    clock += 30 * 60 * 1000;
    expect(await readAppSession(hub, true, jar(forged), new Headers({ [GRACE_HEADER]: "1" }))).toBeNull();
  });
});

// ── The launcher's list of apps ─────────────────────────────────────────────
// ⛔ A DISPLAY LIST. Every test below says which SOURCE decided the value it
// checks: the hub's answer, the cookie the browser sent, or neither.

/** A /token answer carrying whatever the hub put in `apps`. */
const grantWithApps = async (apps: unknown, over?: Parameters<typeof mint>[0]) =>
  new Response(JSON.stringify({ token: await mint(over), handle: "h-next", expires_in: 900, apps }), { status: 200 });
/** The 0.1.2 answer: no `apps` field at all. */
const grantWithoutApps = async () =>
  new Response(JSON.stringify({ token: await mint(), handle: "h-next", expires_in: 900 }), { status: 200 });
const appsCookie = (res: Response) => setCookie(res, names.apps);
const jarOf = (cookies: Record<string, string>) => ({
  get: (n: string) => (n in cookies ? { value: cookies[n] } : undefined),
});

describe("the launcher's list: what counts as one", () => {
  it("app keys only, and anything else is NO list rather than an empty one", () => {
    expect(launcherAppsFrom(["home", "marketing-events-publish"])).toEqual(["home", "marketing-events-publish"]);
    expect(launcherAppsFrom([])).toEqual([]);
    // ⛔ Each of these is absent, and none of them throws.
    expect(launcherAppsFrom(undefined)).toBeNull();          // an older hub
    expect(launcherAppsFrom(null)).toBeNull();
    expect(launcherAppsFrom("home,people")).toBeNull();      // not an array
    expect(launcherAppsFrom({ 0: "home", length: 1 })).toBeNull();
    expect(launcherAppsFrom(["home", 7])).toBeNull();        // not all strings
    expect(launcherAppsFrom(["home", null])).toBeNull();
    expect(launcherAppsFrom(["Home"])).toBeNull();           // not the key shape
    expect(launcherAppsFrom(["1home"])).toBeNull();
    expect(launcherAppsFrom(["h"])).toBeNull();
    expect(launcherAppsFrom(["home.people"])).toBeNull();    // the separator itself
    expect(launcherAppsFrom(["a b"])).toBeNull();
  });

  it("the two bounds are reached one at a time, so neither hides the other", () => {
    const short = Array.from({ length: LAUNCHER_APPS_MAX_COUNT }, () => "home");
    expect(launcherAppsFrom(short)).toHaveLength(LAUNCHER_APPS_MAX_COUNT);
    expect(launcherAppsFrom([...short, "home"])).toBeNull();           // one too many
    // Twenty-five of the longest key a hub will ever issue: well inside the
    // count, and past what a cookie should carry.
    const long = Array.from({ length: 25 }, () => `a${"b".repeat(40)}`);
    expect(long.length).toBeLessThan(LAUNCHER_APPS_MAX_COUNT);
    expect(encodeLauncherApps(long).length).toBeGreaterThan(LAUNCHER_APPS_MAX_BYTES);
    expect(launcherAppsFrom(long)).toBeNull();                          // too large
  });

  it("the whole of today's estate fits with room to spare", () => {
    // The hub's canonical order, 20 November 2026. The worst list anybody can
    // actually hold, measured rather than guessed.
    const estate = [
      "home", "product", "productedit", "productadmin", "people", "values", "marketing", "marketing-events",
      "marketing-events-publish", "sales", "leadership", "scheduling", "scheduleedit", "studentreporting",
      "mentorcost", "placementsedit", "placementsadmin", "finance", "partnerships", "cms", "audit", "governance",
      "launchpad", "admin",
    ];
    expect(estate).toHaveLength(24);
    expect(encodeLauncherApps(estate)).toHaveLength(262);
    expect(launcherAppsFrom(estate)).toEqual(estate);
    // Name, "=", value: what the browser actually carries, against its ~4096.
    expect(`${names.apps}=${encodeLauncherApps(estate)}`.length).toBeLessThan(300);
  });

  it("a cookie value survives the round trip, and an EMPTY list is not an ABSENT one", () => {
    expect(parseLauncherApps(encodeLauncherApps(["home", "people"]))).toEqual(["home", "people"]);
    expect(parseLauncherApps(encodeLauncherApps([]))).toEqual([]);
    expect(encodeLauncherApps([])).toBe(".");
    // ⛔ No cookie, a cleared cookie and rubbish in one are all ABSENT.
    expect(parseLauncherApps(undefined)).toBeNull();
    expect(parseLauncherApps("")).toBeNull();
    expect(parseLauncherApps("home.people")).toBeNull();   // no leading marker
    expect(parseLauncherApps(".home..people")).toBeNull(); // an empty key
    expect(parseLauncherApps(`.${"x".repeat(LAUNCHER_APPS_MAX_BYTES)}`)).toBeNull();
    expect(parseLauncherApps(".".repeat(LAUNCHER_APPS_MAX_BYTES))).toBeNull();
  });
});

describe("the launcher's list: finishing a sign-in", () => {
  const pending = JSON.stringify({ s: "state-1", v: "verifier-1", r: "/people" });
  const signIn = (o: Partial<AppSessionOptions> = {}) =>
    setup(o).handle(request("/session/callback?code=c1&state=state-1", { cookies: { [names.state]: pending } }));

  it("stores what the HUB sent, in a cookie by the same rules as the token's", async () => {
    hubState.token = () => grantWithApps(["home", "people", "marketing"]);
    const res = (await signIn())!;
    const c = appsCookie(res)!;
    expect(c).toContain(`${names.apps}=.home.people.marketing`);
    expect(c).toContain("HttpOnly");
    expect(c).toContain("Secure");
    expect(c).toContain("Path=/");
    expect(c).not.toContain("Domain=");
    expect(c).toContain(`Max-Age=${30 * 24 * 60 * 60}`); // the token cookie's life
    expect(names.apps).toBe("__Host-cgsi.session-apps");
  });

  it("an EMPTY list from the hub is stored as one, not thrown away", async () => {
    hubState.token = () => grantWithApps([]);
    expect(appsCookie((await signIn())!)).toContain(`${names.apps}=.;`);
  });

  it("⛔ a hub that sends no list leaves no list: the cookie is cleared, and nothing else changes", async () => {
    hubState.token = grantWithoutApps;
    const res = (await signIn())!;
    // Exactly 0.1.2's behaviour for everything else.
    expect(res.headers.get("location")).toBe(`${APP}/people`);
    expect(setCookie(res, names.token)).toContain("HttpOnly");
    expect(setCookie(res, names.handle)).toContain("h-next");
    expect(appsCookie(res)).toContain("Max-Age=0");
  });

  it("⛔ a list the hub mangled is absent, and the sign-in still succeeds", async () => {
    for (const bad of ["home,people", ["Home"], [1, 2], { a: 1 }]) {
      hubState.token = () => grantWithApps(bad);
      const res = (await signIn())!;
      expect(res.headers.get("location")).toBe(`${APP}/people`);
      expect(setCookie(res, names.token)).toBeDefined();
      expect(appsCookie(res)).toContain("Max-Age=0");
    }
  });
});

describe("the launcher's list: renewal", () => {
  const renewing = async (cookies: Record<string, string> = {}) => ({
    [names.token]: await mint({}, { ttl: 30 }), [names.handle]: "h1", ...cookies,
  });

  it("the request that renewed sees the NEW list, not the one it arrived with", async () => {
    hubState.token = () => grantWithApps(["home", "finance"]);
    const cookies = await renewing({ [names.apps]: ".home", other: "x" });
    const res = (await setup().handle(request("/", { cookies })))!;
    // Source: the hub's answer, on this same request.
    expect(forwarded(res)).toContain(`${names.apps}=.home.finance`);
    expect(appsCookie(res)).toContain(`${names.apps}=.home.finance`);
    // ⛔ And the request it arrived with is gone from what server code reads.
    expect(forwarded(res)).not.toContain(`${names.apps}=.home;`);
    expect(forwarded(res)).toContain("other=x");
    // Server code, reading the forwarded jar, gets the hub's list.
    expect(readLauncherApps(true, jarOf({ [names.apps]: ".home.finance" }))).toEqual(["home", "finance"]);
  });

  it("⛔ a value the BROWSER put in the cookie is replaced by the hub's at the renewal", async () => {
    hubState.token = () => grantWithApps(["home"]);
    const cookies = await renewing({ [names.apps]: ".admin.finance.leadership" });
    const res = (await setup().handle(request("/", { cookies })))!;
    expect(forwarded(res)).toContain(`${names.apps}=.home`);
    expect(forwarded(res)).not.toContain("admin");
  });

  it("⛔ a hub that stopped sending a list clears the stale one, on this request too", async () => {
    hubState.token = grantWithoutApps;
    const res = (await setup().handle(request("/", { cookies: await renewing({ [names.apps]: ".home.finance" }) })))!;
    expect(forwarded(res)).not.toContain(names.apps);
    expect(appsCookie(res)).toContain("Max-Age=0");
    // Absent, not empty: an app knows to fall back to its own source.
    expect(readLauncherApps(true, jarOf({}))).toBeNull();
  });

  it("⛔ an internal header a browser sent is still stripped on the renewal path", async () => {
    hubState.token = () => grantWithApps(["home"]);
    const res = (await setup().handle(request("/", {
      headers: { [GRACE_HEADER]: "1" }, cookies: await renewing(),
    })))!;
    expect(res.headers.get(`x-middleware-request-${GRACE_HEADER}`)).toBeNull();
    expect(forwarded(res)).toContain(`${names.apps}=.home`);
  });

  it("a renewal the hub could not answer leaves the list exactly as it was", async () => {
    const old = await mint();
    const { handle, hub } = setup();
    await hub.check(old);
    hubState.token = down;
    clock += 50 * 60 * 1000;
    const res = (await handle(request("/", { cookies: { [names.token]: old, [names.handle]: "h1", [names.apps]: ".home" } })))!;
    expect(res.headers.get("x-middleware-next")).toBe("1");
    expect(appsCookie(res)).toBeUndefined();              // untouched
    expect(forwarded(res)).toContain(`${names.apps}=.home`);
  });
});

describe("the launcher's list: when it is cleared", () => {
  it("signing out clears it with the rest", async () => {
    const res = (await setup().handle(request("/session/signout")))!;
    for (const n of [names.token, names.handle, names.apps]) expect(setCookie(res, n)).toContain("Max-Age=0");
  });

  it("a session the hub has ended clears it, and server code never sees it", async () => {
    const cookies = { "__Secure-authjs.session-token": "legacy", [names.token]: await mint({}, { ttl: 30 }), [names.handle]: "h1", [names.apps]: ".home" };
    const res = (await setup({ mode: "both" }).handle(request("/people", { cookies, headers: { "sec-fetch-dest": "empty" } }), { legacySignedIn: true }))!;
    expect(res.headers.get("x-middleware-next")).toBe("1");
    expect(forwarded(res)).not.toContain(names.apps);
    expect(appsCookie(res)).toContain("Max-Age=0");
  });

  it("the hub saying no access clears it too", async () => {
    hubState.token = () => new Response("{}", { status: 403 });
    const cookies = { [names.token]: await mint({}, { ttl: 30 }), [names.handle]: "h1", [names.apps]: ".home" };
    const res = (await setup().handle(request("/", { cookies })))!;
    expect(res.headers.get("location")).toBe(`${HUB}/no-access?app=console`);
    expect(appsCookie(res)).toContain("Max-Age=0");
  });
});

describe("the launcher's list: requests that share one renewal", () => {
  it("every sharer of a single call gets the same list from it", async () => {
    hubState.token = () => grantWithApps(["home", "audit"]);
    const { hub } = setup();
    const answers = await Promise.all([1, 2, 3, 4, 5].map(() => hub.renew("h1")));
    expect(tokenCalls()).toBe(1);
    for (const a of answers) {
      expect(a).toBe(answers[0]);
      expect(a.ok && a.launcherApps).toEqual(["home", "audit"]);
    }
  });
});

describe("the launcher's list: server code reading it", () => {
  it("the cookie is the only source, and a missing or broken one is absent", () => {
    expect(readLauncherApps(true, jarOf({ [names.apps]: ".home.people" }))).toEqual(["home", "people"]);
    expect(readLauncherApps(true, jarOf({ [names.apps]: "." }))).toEqual([]);
    expect(readLauncherApps(true, jarOf({}))).toBeNull();
    expect(readLauncherApps(true, jarOf({ [names.apps]: "home.people" }))).toBeNull();
    // Away from https the cookie loses the prefix, exactly as the token's does.
    expect(readLauncherApps(false, jarOf({ "cgsi.session-apps": ".home" }))).toEqual(["home"]);
    expect(readLauncherApps(false, jarOf({ [names.apps]: ".home" }))).toBeNull();
  });

  it("⛔ it is nowhere near the session: readAppSession still answers only from the token", async () => {
    const { hub } = setup();
    const token = await mint();
    const session = await readAppSession(hub, true, jarOf({ [names.token]: token, [names.apps]: ".admin" }));
    expect(session).not.toBeNull();
    expect(session).not.toHaveProperty("launcherApps");
    expect(session).not.toHaveProperty("apps");
    expect(Object.keys(session!).sort()).toEqual(
      ["appRole", "departments", "email", "expiresAt", "kind", "loginProvider", "name", "role", "sid", "subject"],
    );
  });
});
