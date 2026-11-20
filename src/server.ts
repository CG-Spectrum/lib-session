// For server code (pages, layouts, actions, route handlers): who is signed in?
//
//   const session = await readAppSession(reader, await cookies(), await headers());
//
// ⛔ Always checks the token itself. It never trusts a header to say who the
// person is. The one header it reads only widens the TIME window for a token
// the hub genuinely signed, when the middleware found the hub unreachable.
import { GRACE_HEADER, HUB_DOWN_GRACE_SECONDS, cookieNames, parseLauncherApps, type AppSession } from "./core";
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
 */
export function readLauncherApps(secure: boolean, cookies: CookieReader): string[] | null {
  return parseLauncherApps(cookies.get(cookieNames(secure).apps)?.value);
}
