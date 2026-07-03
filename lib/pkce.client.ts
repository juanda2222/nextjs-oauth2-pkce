/**
 * PKCE (Proof Key for Code Exchange, RFC 7636) — the app/SDK side.
 *
 * The problem PKCE solves here
 * ----------------------------
 * In this flow the one-time authorization code is minted by the Token
 * Exchange Service and travels back to the app THROUGH THE PARTNER BACKEND
 * (see README diagram). That means the code passes through hands that must
 * not be able to redeem it: the partner's backend, its logs, and the
 * backend→app response hop.
 *
 * PKCE binds the code to the one app instance that started the sign-in:
 *
 *   1. Before asking for a code, the app invents a random secret: the
 *      `code_verifier`. It stays in memory on this device — it is never
 *      sent to the partner backend, persisted, or logged.
 *   2. The app sends only its SHA-256 hash, the `code_challenge`. The
 *      backend relays it verbatim; the Token Exchange Service stores it
 *      next to the code it mints.
 *   3. When exchanging the code for tokens, the app must present the
 *      original `code_verifier`. The service hashes it and compares with
 *      the stored challenge. Anyone else who saw the code — including the
 *      partner backend itself — only ever saw the hash, and a hash cannot
 *      be reversed, so the code is useless to them.
 *
 * Compare with the classic redirect-based flow: there PKCE protects a code
 * that leaks from browser redirects. Same mechanism, different weak link.
 *
 * Everything below is web-standard crypto — no libraries.
 */

import { bytesToBase64Url } from "./base64url.shared";

/**
 * Step 1: the code_verifier.
 *
 * RFC 7636 requires 43–128 characters from [A-Za-z0-9-._~]. 32 random bytes
 * base64url-encoded gives exactly 43 characters (256 bits of entropy).
 *
 * `crypto.getRandomValues` is a cryptographically secure RNG. Never use
 * `Math.random()` for anything security-related: it is predictable.
 *
 * Note there is no sessionStorage here. The redirect flow needs to persist
 * the verifier across a full-page navigation; this flow never leaves the
 * page, so the verifier lives in a local variable and dies with the flow.
 */
export function createCodeVerifier(): string {
  const randomBytes = crypto.getRandomValues(new Uint8Array(32));
  return bytesToBase64Url(randomBytes);
}

/**
 * Step 2: the code_challenge = BASE64URL(SHA256(code_verifier)).
 *
 * This is the "S256" challenge method. The RFC also defines "plain"
 * (challenge = verifier, no hashing) — never use it: it would hand the
 * partner backend the verifier itself, defeating the whole point.
 */
export async function createCodeChallenge(codeVerifier: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(codeVerifier),
  );
  return bytesToBase64Url(new Uint8Array(digest));
}
