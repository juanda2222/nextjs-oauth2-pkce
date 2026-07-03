/**
 * Helpers for the MOCK authorization server (see app/oauth/*).
 *
 * ─────────────────────────────────────────────────────────────────────────
 * Everything in this file is the PROVIDER's side of the protocol — the part
 * Google/Auth0/Okta run for you. It is included so you can read both halves
 * of the conversation. Your day-to-day job as an app developer is the
 * CLIENT side (lib/pkce.ts and the pages under app/).
 * ─────────────────────────────────────────────────────────────────────────
 *
 * A real authorization server stores issued codes and tokens in a database.
 * To keep this demo dependency-free and stateless, we instead make the code
 * and token *self-describing*: a JSON payload plus an HMAC-SHA256 signature,
 * both base64url-encoded, joined by a dot:
 *
 *     base64url(payload-json) + "." + base64url(hmac-signature)
 *
 * Only someone who knows the server secret can produce a valid signature,
 * so the server can trust anything whose signature verifies. (If this shape
 * reminds you of a JWT — yes, a JWT is this same idea with an extra header.)
 */

import { base64UrlToString, bytesToBase64Url, stringToBase64Url } from "./base64url";

/**
 * Demo-only secret. A real server keeps this in a secrets manager and
 * rotates it. If it leaks, anyone can mint valid tokens.
 */
const SIGNING_SECRET =
  process.env.MOCK_PROVIDER_SECRET ?? "demo-only-secret-never-do-this-in-production";

/** The one client this provider knows about (a real one has a registry). */
export const REGISTERED_CLIENT_ID = "demo-public-client";

/** The fake user that "logs in" on the consent screen. */
export const DEMO_USER = {
  sub: "user-42", // "subject": the stable unique user id
  name: "Ada Lovelace",
  email: "ada@example.com",
};

async function getSigningKey(): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(SIGNING_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

/** Serialize + sign a payload. Used to mint authorization codes and access tokens. */
export async function signPayload(payload: object): Promise<string> {
  const encodedPayload = stringToBase64Url(JSON.stringify(payload));
  const key = await getSigningKey();
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(encodedPayload),
  );
  return `${encodedPayload}.${bytesToBase64Url(new Uint8Array(signature))}`;
}

/**
 * Verify signature + expiry and return the payload, or null if anything is
 * off. `crypto.subtle.verify` does a constant-time comparison — comparing
 * signatures with `===` would leak information through timing differences.
 */
export async function verifyPayload<T extends { expiresAt: number }>(
  token: string,
): Promise<T | null> {
  const [encodedPayload, encodedSignature] = token.split(".");
  if (!encodedPayload || !encodedSignature) return null;

  let signatureBytes: Uint8Array<ArrayBuffer>;
  try {
    const binary = atob(encodedSignature.replace(/-/g, "+").replace(/_/g, "/"));
    signatureBytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      signatureBytes[i] = binary.charCodeAt(i);
    }
  } catch {
    return null;
  }

  const key = await getSigningKey();
  const isValid = await crypto.subtle.verify(
    "HMAC",
    key,
    signatureBytes,
    new TextEncoder().encode(encodedPayload),
  );
  if (!isValid) return null;

  let payload: T;
  try {
    payload = JSON.parse(base64UrlToString(encodedPayload));
  } catch {
    return null;
  }

  if (typeof payload.expiresAt !== "number" || Date.now() > payload.expiresAt) {
    return null; // expired
  }
  return payload;
}

/**
 * The provider-side half of PKCE: hash the verifier the same way the client
 * did (S256) so the token endpoint can compare it against the challenge it
 * received at the start of the flow.
 */
export async function computeS256Challenge(codeVerifier: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(codeVerifier),
  );
  return bytesToBase64Url(new Uint8Array(digest));
}

/** What the provider packs into an authorization code. */
export type AuthorizationCodePayload = {
  kind: "authorization_code";
  sub: string;
  clientId: string;
  redirectUri: string;
  codeChallenge: string; // <- the PKCE challenge, stored until the exchange
  scope: string;
  expiresAt: number;
};

/** What the provider packs into an access token. */
export type AccessTokenPayload = {
  kind: "access_token";
  sub: string;
  clientId: string;
  scope: string;
  expiresAt: number;
};
