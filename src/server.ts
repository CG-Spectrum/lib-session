// For server code (pages, layouts, actions, route handlers): who is signed in?
//
//   const session = await readAppSession(reader, await cookies(), await headers());
//
// ⛔ Always checks the token itself. It never trusts a header to say who the
// person is. The one header it reads only widens the TIME window for a token
// the hub genuinely signed, when the middleware found the hub unreachable.
import { GRACE_HEADER, HUB_DOWN_GRACE_SECONDS, cookieNames, type AppSession } from "./core";
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
