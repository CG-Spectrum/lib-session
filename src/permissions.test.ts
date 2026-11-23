// The permissions claim (display) and the live permission check (decisions).
// The claim is read from a token signed with a real key and verified by the
// real hub client; the check talks to a stand-in hub.
import { SignJWT, exportJWK, generateKeyPair } from "jose";
import { describe, expect, it } from "vitest";
import { createHub } from "./hub";
import {
  HUB_PERMISSION_CHECK_TIMEOUT_MS, createPermissionCheck, personFromSession, showsPermission,
} from "./permissions";
import type { AppSession } from "./core";

const HUB = "https://auth.cgspectrum.com";
const KEY = "k".repeat(43);
const key = await generateKeyPair("ES256", { extractable: true });
const jwks = { keys: [{ ...(await exportJWK(key.publicKey)), kid: "k1", alg: "ES256", use: "sig" }] };

async function verified(claims: Record<string, unknown>): Promise<AppSession> {
  const now = Math.floor(Date.now() / 1000);
  const token = await new SignJWT({
    sid: "s1", email: "a@cgspectrum.com", name: "A", gsub: "user_01ABC", lprov: "workos", kind: "staff",
    role: "staff", departments: [], appRole: null, ...claims,
  }).setProtectedHeader({ alg: "ES256", kid: "k1" }).setIssuer(HUB).setAudience("console")
    .setIssuedAt(now).setExpirationTime(now + 900).sign(key.privateKey);
  const hub = createHub({
    app: "console", hubUrl: HUB,
    fetch: (async () => new Response(JSON.stringify(jwks), { status: 200 })) as typeof fetch,
  });
  const c = await hub.check(token);
  if (c.state !== "valid") throw new Error(`token ${c.state}`);
  return c.session;
}

type Call = { url: string; init: RequestInit; body: Record<string, unknown> };
function standIn(answer: (c: Call) => Response | Promise<Response>) {
  const calls: Call[] = [];
  const logs: string[] = [];
  const fetchFn = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const c = { url: String(input), init: init ?? {}, body: JSON.parse(String(init?.body ?? "{}")) };
    calls.push(c);
    return answer(c);
  }) as typeof fetch;
  // `pc()` is this app with its key; `pc(k)` is the same app with key `k`, undefined included.
  const pc = (...k: [] | [string | undefined]) =>
    createPermissionCheck({ hubUrl: `${HUB}/`, serviceKey: k.length ? k[0] : KEY, fetch: fetchFn, log: (m) => logs.push(m) });
  return { calls, logs, pc };
}
const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

describe("the claim: what to SHOW", () => {
  it("reads the signed claim into the session", async () => {
    const s = await verified({ permissions: ["app.home.open", "app.people.open"] });
    expect(s.permissions).toEqual(["app.home.open", "app.people.open"]);
    expect(showsPermission(s, "app.home.open")).toBe(true);
    expect(showsPermission(s, "app.product.open")).toBe(false);
  });
  it("absent is null, not empty, and shows nothing", async () => {
    const s = await verified({});
    expect(s.permissions).toBeNull();
    expect(showsPermission(s, "app.home.open")).toBe(false);
  });
  it("an empty claim shows nothing; nobody signed in shows nothing", async () => {
    expect(showsPermission(await verified({ permissions: [] }), "app.home.open")).toBe(false);
    expect(showsPermission(null, "app.home.open")).toBe(false);
    expect(showsPermission(undefined, "app.home.open")).toBe(false);
  });
  it("a claim that is not a list is no claim", async () => {
    expect((await verified({ permissions: "app.home.open" })).permissions).toBeNull();
  });
  it("personFromSession is the login the hub signed, exactly", async () => {
    expect(personFromSession(await verified({}))).toEqual({ login: { provider: "workos", subject: "user_01ABC" } });
  });
});

describe("the check: what to OPEN or WRITE", () => {
  it("held only from a 200 saying { held: true }", async () => {
    const { calls, pc } = standIn(() => json(200, { held: true }));
    expect(await pc().check({ login: { provider: "workos", subject: "user_01ABC" } }, "app.home.open")).toBe("held");
    const [c] = calls;
    expect(c!.url).toBe(`${HUB}/permissions/check`);
    expect(c!.init.method).toBe("POST");
    expect(c!.init.cache).toBe("no-store");
    expect((c!.init.headers as Record<string, string>).authorization).toBe(`Bearer ${KEY}`);
    expect(c!.body).toEqual({ permission: "app.home.open", login: { provider: "workos", subject: "user_01ABC" } });
  });
  it("sends the address form as exactly the address and the permission", async () => {
    const { calls, pc } = standIn(() => json(200, { held: false }));
    expect(await pc().check({ address: "someone@cgspectrum.com" }, "app.home.open")).toBe("not_held");
    expect(calls[0]!.body).toEqual({ permission: "app.home.open", address: "someone@cgspectrum.com" });
  });
  it("a person reference carries nothing it was not built with", async () => {
    const { calls, pc } = standIn(() => json(200, { held: false }));
    const extra = { login: { provider: "workos", subject: "user_01ABC", email: "x@y" } } as unknown as Parameters<
      ReturnType<typeof pc>["check"]>[0];
    await pc().check(extra, "app.home.open");
    expect(calls[0]!.body).toEqual({ permission: "app.home.open", login: { provider: "workos", subject: "user_01ABC" } });
  });
  it("⛔ every other status is unavailable, which is NO: including 401, 403, 404 and 503", async () => {
    for (const status of [201, 204, 400, 401, 403, 404, 415, 429, 500, 503]) {
      const { pc } = standIn(() => json(status, { held: true }));
      expect(await pc().check({ address: "a@cgspectrum.com" }, "app.home.open"), String(status)).toBe("unavailable");
    }
  });
  it("⛔ a 200 that is not an answer is unavailable", async () => {
    for (const body of [{}, { held: "true" }, { held: 1 }, null, "held"]) {
      const { pc } = standIn(() => json(200, body));
      expect(await pc().check({ address: "a@cgspectrum.com" }, "app.home.open"), JSON.stringify(body)).toBe("unavailable");
    }
    const { pc } = standIn(() => new Response("not json", { status: 200 }));
    expect(await pc().check({ address: "a@cgspectrum.com" }, "app.home.open")).toBe("unavailable");
  });
  it("a network failure and a timeout are unavailable, by NAME, and nothing throws", async () => {
    const net = standIn(() => { throw new TypeError("fetch failed: secret detail"); });
    expect(await net.pc().check({ address: "a@cgspectrum.com" }, "app.home.open")).toBe("unavailable");
    expect(net.logs).toEqual(["permission check unavailable: network"]);
    const slow = standIn(() => { throw Object.assign(new Error("x"), { name: "TimeoutError" }); });
    expect(await slow.pc().check({ address: "a@cgspectrum.com" }, "app.home.open")).toBe("unavailable");
    expect(slow.logs).toEqual(["permission check unavailable: timeout"]);
  });
  it("asks with a timeout, and the timeout is the capability check's", async () => {
    const { calls, pc } = standIn(() => json(200, { held: true }));
    await pc().check({ address: "a@cgspectrum.com" }, "app.home.open");
    expect(calls[0]!.init.signal).toBeInstanceOf(AbortSignal);
    expect(HUB_PERMISSION_CHECK_TIMEOUT_MS).toBe(4000);
  });
  it("no key, or a malformed one: unavailable, and the hub is never called", async () => {
    for (const k of [undefined, "", "short", "has a space in it, long enough"]) {
      const { calls, pc, logs } = standIn(() => json(200, { held: true }));
      expect(await pc(k).check({ address: "a@cgspectrum.com" }, "app.home.open")).toBe("unavailable");
      expect(calls).toEqual([]);
      expect(logs).toEqual(["permission check unavailable: no key"]);
    }
  });
  it("a hub address that is not https: unavailable, and the key is never sent", async () => {
    for (const hubUrl of ["http://auth.cgspectrum.com", "auth.cgspectrum.com", "ftp://auth.cgspectrum.com", "http://localhost.evil.com"]) {
      const calls: unknown[] = [];
      const logs: string[] = [];
      const pc = createPermissionCheck({
        hubUrl, serviceKey: KEY, log: (m) => logs.push(m),
        fetch: (async () => { calls.push(1); return json(200, { held: true }); }) as typeof fetch,
      });
      expect(await pc.check({ address: "a@cgspectrum.com" }, "app.home.open")).toBe("unavailable");
      expect(calls).toEqual([]);
      expect(logs).toEqual(["permission check unavailable: hub address is not https"]);
    }
  });
  it("plain http to this machine is allowed, for local development", async () => {
    for (const hubUrl of ["http://localhost:3000", "http://127.0.0.1:3000/", "http://[::1]:3000"]) {
      const pc = createPermissionCheck({
        hubUrl, serviceKey: KEY, log: () => {},
        fetch: (async () => json(200, { held: true })) as typeof fetch,
      });
      expect(await pc.check({ address: "a@cgspectrum.com" }, "app.home.open")).toBe("held");
    }
  });
  it("never caches: two checks are two calls, and a changed answer is seen at once", async () => {
    let held = true;
    const { calls, pc } = standIn(() => json(200, { held }));
    const check = pc();
    expect(await check.check({ address: "a@cgspectrum.com" }, "app.home.open")).toBe("held");
    held = false;
    expect(await check.check({ address: "a@cgspectrum.com" }, "app.home.open")).toBe("not_held");
    expect(calls).toHaveLength(2);
  });
  it("⛔ no log line carries the key, the person or the permission", async () => {
    const { pc, logs } = standIn(() => json(503, { error: "unavailable" }));
    await pc().check({ login: { provider: "workos", subject: "user_01ABC" } }, "app.home.open");
    const all = logs.join(" ");
    for (const v of [KEY, "user_01ABC", "app.home.open"]) expect(all).not.toContain(v);
  });
});
