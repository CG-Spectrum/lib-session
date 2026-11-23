// For server code (pages, layouts, actions, route handlers): who is signed in?
//
//   const session = await readAppSession(reader, await cookies(), await headers());
//
// ⛔ Always checks the token itself. It never trusts a header to say who the
// person is. The one header it reads only widens the TIME window for a token
// the hub genuinely signed, when the middleware found the hub unreachable.
import {
  GRACE_HEADER, HUB_DOWN_GRACE_SECONDS, cookieNames, parseLauncherApps,
  type AppSession, type CapabilityNow,
} from "./core";
import type { Hub } from "./hub";

interface CookieReader { get(name: string): { value: string } | undefined }
interface HeaderReader { get(name: string): string | null }

export async function readAppSession(
  hub: Hub, secure: boolean, cookies: CookieReader, headers?: HeaderReader,
): Promise<AppSession | null> {
  const checked = await hub.check(cookies.get(cookieNames(secure).token)?.value);
  if (checked.state === "valid") return checked.session;
  if (
    checked.state === "expired" && headers?.get(GRACE_HEADER) === "1" &&
    checked.expiredForSeconds <= HUB_DOWN_GRACE_SECONDS
  ) return checked.session;
  return null;
}

/**
 * The launcher's list of apps the hub last sent, for drawing tiles with.
 *
 * ⛔ UNSIGNED, AND IT DECIDES NOTHING. It is read from a cookie and nothing
 * about it is signed, so a person can put anything in it. It is a SIBLING of
 * `readAppSession` and deliberately not part of what that returns: an
 * `AppSession` is a verified token's claims, and an unsigned value has no
 * business sitting among them where somebody might reach for it as one.
 *
 *   const session = await readAppSession(hub, secure, await cookies(), await headers());
 *   const tiles = readLauncherApps(secure, await cookies());
 *
 * `null` means the hub sent no list: an older hub, a person the list does not
 * apply to, or nothing usable in the cookie. That is NOT an empty list, and an
 * app moving off the shared cookie should fall back to its old source on null
 * and show nothing on `[]`.
 *
 * ⚖️ THE ONE THAT MAY DECIDE IS THE OTHER ONE. If the question is "may this
 * person do X here", the answer is `hasCapability(session, "x")`, which reads
 * the verified token. This function answers "what tiles shall I draw" and
 * nothing else.
 */
export function readLauncherApps(secure: boolean, cookies: CookieReader): string[] | null {
  return parseLauncherApps(cookies.get(cookieNames(secure).apps)?.value);
}

/**
 * ✅ DOES THIS PERSON HOLD THIS KEY RIGHT NOW? Asks the hub, in this call, and
 * answers one of three words.
 *
 *   const now = await checkCapabilityNow(hub, secure, await cookies(), await headers(), "values");
 *   if (now !== "held") return tryAgainPage();   // ⛔ "unavailable" is NO
 *
 * ⚖️ WHEN TO USE WHICH, and the rule that needs both:
 *
 *   hasCapability(session, key)   the SIGNED claim. Fast, free, up to 15
 *                                 minutes old. ✅ Decides what to SHOW.
 *   checkCapabilityNow(...)       the hub, now. One network call. ✅ Decides
 *                                 what to OPEN or WRITE.
 *
 * A key over money or personal records needs BOTH: the claim to draw the tab,
 * this to serve the page or take the write. Showing a tab that then refuses is
 * a cosmetic cost; opening a record on a grant withdrawn fourteen minutes ago
 * is not.
 *
 * ⛔ ANYTHING OTHER THAN "held" MEANS NO, and that emphatically includes
 * "unavailable". There is no grace here and no benefit of the doubt: the
 * package carries an EXPIRED token for up to an hour when the hub cannot be
 * reached, which is right for ordinary browsing and wrong for this, so a
 * request on the grace path is refused before the hub is asked at all.
 *
 * ⛔ NEVER THROWS. Every failure is a word.
 */
export async function checkCapabilityNow(
  hub: Hub,
  secure: boolean,
  cookies: CookieReader,
  headers: HeaderReader | undefined,
  key: string,
): Promise<CapabilityNow> {
  try {
    // ⚖️ THE CURRENT TOKEN, NOT THE ONE THE BROWSER SENT. The middleware may
    // have renewed on this very request; when it does it rewrites the
    // request's own cookies before server code runs, so this is the token just
    // issued. The same source `readAppSession` reads, for the same reason: two
    // readers taking the token from two places is how a just-renewed session
    // ends up presenting a token the hub has moved on from.
    const token = cookies.get(cookieNames(secure).token)?.value;
    if (!token) return "not_held";
    // ⛔ THE GRACE MARKER IS READ IN ORDER TO REFUSE IT. The middleware sets it
    // when a renewal on this request could not reach the hub and it is
    // carrying an expired token. That is exactly the state a sensitive
    // decision must not be made in, and asking the hub would be pointless
    // besides: it could not be reached a moment ago.
    if (headers?.get(GRACE_HEADER) === "1") return "not_held";
    // Checked here, so a token this app would not itself accept is never
    // presented to the hub: no token, an expired one and one the hub did not
    // sign are all "not_held" without a call.
    if ((await hub.check(token)).state !== "valid") return "not_held";
    return await hub.checkCapability(token, key);
  } catch {
    // Nothing above should throw. If something does, it is not a yes.
    return "unavailable";
  }
}
