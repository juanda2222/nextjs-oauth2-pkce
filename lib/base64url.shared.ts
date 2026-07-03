/**
 * base64url (RFC 4648 §5) helpers.
 *
 * OAuth 2.0 / PKCE uses "base64url" everywhere instead of plain base64:
 * it is the same encoding, but `+` becomes `-`, `/` becomes `_`, and the
 * trailing `=` padding is removed, so the result is safe to put in a URL
 * without percent-encoding.
 *
 * These helpers use only web-standard APIs (btoa/atob, TextEncoder), so the
 * exact same code runs in the browser AND in Next.js route handlers.
 */

export function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function stringToBase64Url(text: string): string {
  return bytesToBase64Url(new TextEncoder().encode(text));
}

export function base64UrlToString(encoded: string): string {
  // Restore standard base64 so atob() accepts it.
  const base64 = encoded.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(base64);
  const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}
