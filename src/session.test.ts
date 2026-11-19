import { SignJWT, exportJWK, generateKeyPair } from "jose";
import { NextRequest } from "next/server";
import { beforeEach, describe, expect, it } from "vitest";
import {
  GRACE_HEADER, cookieNames, isPageNavigation, originAllowed, originGuardMode, readPending, safeReturnTo, sessionMode,
} from "./core";
import { createHub } from "./hub";
import { createSessionMiddleware, type AppSessionOptions } from "./middleware";
import { readAppSession } from "./server";

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
