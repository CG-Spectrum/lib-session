// Permissions from the access model, for an app: one claim to DRAW with, and
// one live check to DECIDE with.
//
//   showsPermission(session, "app.home.open")     the signed `permissions`
//                                                 claim. Fast, free, up to 15
//                                                 minutes old. ✅ What to SHOW.
//   permissions.check(person, "app.home.open")    the hub, now, server to
//                                                 server, with this app's own
//                                                 key. ✅ What to OPEN or WRITE.
//   permissions.checkMany(person, [..keys])       the same, for up to 16 keys
//                                                 in ONE request: a page that
//                                                 needs several asks once.
//
// ⛔ THE CLAIM DECIDES NOTHING. Every write, and every read of student records
// or money, calls the check at the moment it decides. Showing a tab that then
// refuses is a cosmetic cost; acting on a permission withdrawn fourteen minutes
// ago is not.
//
// ⚖️ A YES FOR A SCOPED PERMISSION IS NECESSARY, NOT SUFFICIENT. A permission
// held on a caseload or on disciplines answers "held": the person holds it for
// SOME records. The app still applies the scope.
import type { AppSession } from "./core";

/**
 * How long to wait for the hub's answer. The same as the capability check:
 * the hub bounds its own work far more tightly than a renewal, and a person is
 * waiting. ⛔ A timeout is a refusal, never a grace.
 */
export const HUB_PERMISSION_CHECK_TIMEOUT_MS = 4000;

/** The most keys one `checkMany` may ask about, after duplicates are folded. The hub's own cap. */
export const HUB_PERMISSION_CHECK_MAX = 16;

/**
 * ⛔ THREE WORDS, AND NEVER A BOOLEAN. An app given `true | false` has nowhere
 * to put "the hub could not be asked", and will put it in one of the two.
 *
 *   held         the hub said yes, in this call, just now
 *   not_held     the hub said no
 *   unavailable  the hub could not be asked, refused this app, or did not
 *                answer usefully
 *
 * ⚖️ ANYTHING BUT "held" IS NO.
 */
export type PermissionNow = "held" | "not_held" | "unavailable";

/** Who the check is about: exactly one of the two forms the hub accepts. */
export type PermissionPerson =
  | { login: { provider: string; subject: string } }
  | { address: string };

/**
 * May this be SHOWN? True only when the verified token's `permissions` claim
 * lists the key. Nobody signed in, an absent claim and an empty one are all
 * false, so a menu written this way shows less rather than more.
 * ⛔ Never a decision: see `createPermissionCheck`.
 */
export function showsPermission(session: AppSession | null | undefined, key: string): boolean {
  return !!session && Array.isArray(session.permissions) && session.permissions.includes(key);
}

/**
 * The signed-in person as the check's login form: exactly the login the hub
 * signed into the token, so an app never assembles a reference by hand.
 */
export function personFromSession(session: AppSession): PermissionPerson {
  return { login: { provider: session.loginProvider, subject: session.subject } };
}

export interface PermissionCheckOptions {
  /** The hub, e.g. https://auth.cgspectrum.com. */
  hubUrl: string;
  /**
   * THIS app's own key for the check, from the app's server environment
   * (`HUB_PERMISSION_CHECK_KEY` by convention). The package reads no
   * environment variable itself. ⛔ Server code only: never sent to a browser.
   */
  serviceKey: string | undefined;
  /** For tests. */
  fetch?: typeof fetch;
  /**
   * Where a reason word goes. ⛔ A WORD, NEVER A VALUE: no key, no person, no
   * permission. Defaults to a warning on the console.
   */
  log?: (message: string) => void;
}

export interface PermissionCheck {
  /**
   * Does this person hold this permission RIGHT NOW? One POST to the hub.
   * ⛔ Never throws, never caches, and never answers "held" without a 200 from
   * the hub saying so in THIS call.
   */
  check(person: PermissionPerson, permission: string): Promise<PermissionNow>;
  /**
   * The same question for several permissions, in ONE POST: one request of
   * the hub's rate limit, one record on the hub. Every key asked is in the
   * answer. ⛔ ALL OR NOTHING: "held" / "not_held" only when the hub answered
   * EVERY key in this call; any failure at all and EVERY key is "unavailable".
   * Duplicates are folded. More than HUB_PERMISSION_CHECK_MAX distinct keys is
   * refused here, without a request, as all "unavailable". No keys asks
   * nothing and answers `{}`. Never throws, never caches.
   */
  checkMany<K extends string>(person: PermissionPerson, permissions: readonly K[]): Promise<Record<K, PermissionNow>>;
}

const KEY = /^[\x21-\x7e]{16,512}$/;
/** The key travels in a header, so the hub must be HTTPS. Plain HTTP only to this machine, for local development. */
const SAFE_HUB = /^(https:\/\/[^\s/]+|http:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d+)?)(\/|$)/;

export function createPermissionCheck(o: PermissionCheckOptions): PermissionCheck {
  const base = o.hubUrl.replace(/\/$/, "");
  const doFetch: typeof fetch = o.fetch ?? ((...a) => fetch(...a));
  const log = o.log ?? ((m: string) => console.warn(`[session] ${m}`));
  const personBody = (person: PermissionPerson) => ("login" in person
    ? { login: { provider: person.login.provider, subject: person.login.subject } }
    : { address: person.address });

  /**
   * Ask the hub once and hand back the 200's parsed body, or null for every
   * way there is no answer, with a reason WORD already logged. `what` names
   * the call in the log: "permission check" or "permission checkMany".
   */
  async function ask(what: string, body: Record<string, unknown>): Promise<Record<string, unknown> | null> {
    // ⛔ No key, no question: an app that forgot its key is refused here,
    // without the hub, rather than sending a request that cannot succeed.
    if (typeof o.serviceKey !== "string" || !KEY.test(o.serviceKey)) {
      log(`${what} unavailable: no key`);
      return null;
    }
    // ⛔ No key over plain HTTP: a misconfigured hub address would send this
    // app's key in clear. Refused here, without a request.
    if (!SAFE_HUB.test(base)) {
      log(`${what} unavailable: hub address is not https`);
      return null;
    }
    let res: Response;
    try {
      res = await doFetch(`${base}/permissions/check`, {
        method: "POST", cache: "no-store", signal: AbortSignal.timeout(HUB_PERMISSION_CHECK_TIMEOUT_MS),
        headers: { "content-type": "application/json", authorization: `Bearer ${o.serviceKey}` },
        body: JSON.stringify(body),
      });
    } catch (e) {
      // ⛔ The NAME of the failure, never the error.
      log(`${what} unavailable: ${(e as Error)?.name === "TimeoutError" ? "timeout" : "network"}`);
      return null;
    }
    // ⚖️ ONLY A 200 IS AN ANSWER. A 401 is this app's key being wrong, a 403
    // a form this app may not use, a 400 a malformed question, a 404 the
    // check switched off, a 503 the hub unable to answer: none of them says
    // anything about the person, and every one of them is no.
    if (res.status !== 200) {
      log(`${what} unavailable: status ${res.status}`);
      return null;
    }
    try {
      const j: unknown = await res.json();
      if (j && typeof j === "object" && !Array.isArray(j)) return j as Record<string, unknown>;
    } catch { /* fall through */ }
    log(`${what} unavailable: body`);
    return null;
  }

  return {
    async check(person, permission) {
      const j = await ask("permission check", { permission, ...personBody(person) });
      if (!j) return "unavailable";
      if (j.held === true) return "held";
      if (j.held === false) return "not_held";
      log("permission check unavailable: body");
      return "unavailable";
    },

    async checkMany<K extends string>(person: PermissionPerson, permissions: readonly K[]) {
      const keys = [...new Set(permissions)];
      const every = (v: PermissionNow) => Object.fromEntries(keys.map((k) => [k, v])) as Record<K, PermissionNow>;
      if (keys.length === 0) return every("unavailable");
      // ⛔ Over the hub's cap: the hub would refuse the whole call, so it is
      // refused here, without a request. Split the page's question, or ask less.
      if (keys.length > HUB_PERMISSION_CHECK_MAX) {
        log("permission checkMany unavailable: too many");
        return every("unavailable");
      }
      const j = await ask("permission checkMany", { permissions: keys, ...personBody(person) });
      if (!j) return every("unavailable");
      // ⛔ EVERY key asked, as a boolean, and no key that was not asked; or
      // no answer for any of them. A partial map is a hub that did not answer.
      const held = j.held;
      if (held && typeof held === "object" && !Array.isArray(held)
          && Object.keys(held).length === keys.length
          && keys.every((k) => Object.prototype.hasOwnProperty.call(held, k)
            && typeof (held as Record<string, unknown>)[k] === "boolean")) {
        const h = held as Record<string, boolean>;
        return Object.fromEntries(keys.map((k) => [k, h[k] === true ? "held" : "not_held"])) as Record<K, PermissionNow>;
      }
      log("permission checkMany unavailable: body");
      return every("unavailable");
    },
  };
}
