/**
 * PKCE (Proof Key for Code Exchange, RFC 7636) — the client side.
 *
 * The problem PKCE solves
 * -----------------------
 * In the classic Authorization Code flow, the authorization server sends the
 * app a temporary `code` via a browser redirect. Redirects are the weak spot:
 * on mobile OSes another app can register the same URL scheme, browser
 * history and logs can leak the URL, etc. Anyone who steals that `code`
 * (and knows the client_id, which is public) can swap it for an access token.
 *
 * PKCE fixes this with a per-login secret that NEVER travels through a
 * redirect:
 *
 *   1. Before redirecting, the app invents a random secret: the
 *      `code_verifier`. It stays on this device.
 *   2. The app sends only its SHA-256 hash, the `code_challenge`, with the
 *      authorization request. The server stores it next to the code.
 *   3. When exchanging the code for tokens, the app must present the original
 *      `code_verifier`. The server hashes it and compares with the stored
 *      challenge. A thief who intercepted the redirect has the code and the
 *      challenge (the hash), but cannot reverse the hash to get the verifier,
 *      so the stolen code is useless.
 *
 * Everything below is web-standard crypto — no libraries.
 */

import { bytesToBase64Url } from "./base64url";

/**
 * Step 1: the code_verifier.
 *
 * RFC 7636 requires 43–128 characters from [A-Za-z0-9-._~]. 32 random bytes
 * base64url-encoded gives exactly 43 characters (256 bits of entropy).
 *
 * `crypto.getRandomValues` is a cryptographically secure RNG. Never use
 * `Math.random()` for anything security-related: it is predictable.
 */
export function createCodeVerifier(): string {
  const randomBytes = crypto.getRandomValues(new Uint8Array(32));
  return bytesToBase64Url(randomBytes);
}

/**
 * Step 2: the code_challenge = BASE64URL(SHA256(code_verifier)).
 *
 * This is the "S256" challenge method. The RFC also defines "plain"
 * (challenge = verifier, no hashing) as a fallback for clients that cannot
 * hash — but every browser can, so plain should never be used on the web.
 */
export async function createCodeChallenge(codeVerifier: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(codeVerifier),
  );
  return bytesToBase64Url(new Uint8Array(digest));
}

/**
 * The `state` parameter — related but NOT part of PKCE.
 *
 * `state` is an opaque random value the app sends with the authorization
 * request; the server echoes it back untouched on the redirect. By checking
 * that the value that comes back is the one we stored, the app rejects
 * callbacks it never initiated (CSRF: an attacker tricking our callback page
 * into completing a login *the attacker* started, logging the victim into
 * the attacker's account).
 *
 * PKCE protects the code exchange; `state` protects the callback. Use both.
 */
export function createState(): string {
  const randomBytes = crypto.getRandomValues(new Uint8Array(16));
  return bytesToBase64Url(randomBytes);
}
