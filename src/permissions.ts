// Permissions from the access model, for an app: one claim to DRAW with, and
// one live check to DECIDE with.
//
//   showsPermission(session, "app.home.open")     the signed `permissions`
//                                                 claim. Fast, free, up to 15
//                                                 minutes old. ✅ What to SHOW.
//   permissions.check(person, "app.home.open")    the hub, now, server to
//                                                 server, with this app's own
//                                                 key. ✅ What to OPEN or WRITE.
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
}

const KEY = /^[\x21-\x7e]{16,512}$/;

export function createPermissionCheck(o: PermissionCheckOptions): PermissionCheck {
  const base = o.hubUrl.replace(/\/$/, "");
  const doFetch: typeof fetch = o.fetch ?? ((...a) => fetch(...a));
  const log = o.log ?? ((m: string) => console.warn(`[session] ${m}`));
  return {
    async check(person, permission) {
      // ⛔ No key, no question: an app that forgot its key is refused here,
      // without the hub, rather than sending a request that cannot succeed.
      if (typeof o.serviceKey !== "string" || !KEY.test(o.serviceKey)) {
        log("permission check unavailable: no key");
        return "unavailable";
      }
      const body = "login" in person
        ? { permission, login: { provider: person.login.provider, subject: person.login.subject } }
        : { permission, address: person.address };
      let res: Response;
      try {
        res = await doFetch(`${base}/permissions/check`, {
          method: "POST", cache: "no-store", signal: AbortSignal.timeout(HUB_PERMISSION_CHECK_TIMEOUT_MS),
          headers: { "content-type": "application/json", authorization: `Bearer ${o.serviceKey}` },
          body: JSON.stringify(body),
        });
      } catch (e) {
        // ⛔ The NAME of the failure, never the error.
        log(`permission check unavailable: ${(e as Error)?.name === "TimeoutError" ? "timeout" : "network"}`);
        return "unavailable";
      }
      // ⚖️ ONLY A 200 IS AN ANSWER. A 401 is this app's key being wrong, a 403
      // a form this app may not use, a 400 a malformed question, a 404 the
      // check switched off, a 503 the hub unable to answer: none of them says
      // anything about the person, and every one of them is no.
      if (res.status !== 200) {
        log(`permission check unavailable: status ${res.status}`);
        return "unavailable";
      }
      try {
        const j = (await res.json()) as { held?: unknown };
        if (j.held === true) return "held";
        if (j.held === false) return "not_held";
      } catch { /* fall through */ }
      log("permission check unavailable: body");
      return "unavailable";
    },
  };
}
