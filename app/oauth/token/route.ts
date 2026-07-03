/**
 * MOCK PROVIDER — Token endpoint (RFC 6749 §3.2 + RFC 7636 §4.6).
 *
 * Flow step 6: the app POSTs the authorization code together with the PKCE
 * `code_verifier`. This is where PKCE actually pays off — the ONE line that
 * matters is the hash comparison below.
 *
 * Note this is a back-channel request: a direct fetch() from app to
 * provider, not a browser redirect. The verifier is never in a URL.
 */

import {
  AccessTokenPayload,
  AuthorizationCodePayload,
  computeS256Challenge,
  REGISTERED_CLIENT_ID,
  signPayload,
  verifyPayload,
} from "@/lib/provider";

/**
 * Single-use enforcement. A real server marks codes as consumed in a
 * database; an in-memory Set works for a single local dev process. (It
 * resets on restart and would not work across serverless instances — that
 * is fine for a demo, and a useful thing to understand about state.)
 */
const consumedCodes = new Set<string>();

export async function POST(request: Request): Promise<Response> {
  // The spec mandates a form-encoded body (§3.2), not JSON.
  const contentType = request.headers.get("content-type") ?? "";
  if (!contentType.includes("application/x-www-form-urlencoded")) {
    return tokenError("invalid_request", "Body must be application/x-www-form-urlencoded");
  }
  const body = new URLSearchParams(await request.text());

  const grantType = body.get("grant_type");
  const code = body.get("code");
  const redirectUri = body.get("redirect_uri");
  const clientId = body.get("client_id");
  const codeVerifier = body.get("code_verifier");

  if (grantType !== "authorization_code") {
    return tokenError("unsupported_grant_type", "Only authorization_code is supported");
  }
  if (!code || !redirectUri || !clientId || !codeVerifier) {
    return tokenError("invalid_request", "code, redirect_uri, client_id and code_verifier are required");
  }

  // ── 1. The code must be one we issued, unexpired... ─────────────────────
  const codePayload = await verifyPayload<AuthorizationCodePayload>(code);
  if (!codePayload || codePayload.kind !== "authorization_code") {
    return tokenError("invalid_grant", "Authorization code is invalid or expired");
  }

  // ── 2. ...never used before... ──────────────────────────────────────────
  // Replayed codes must be rejected (§4.1.2) — and a robust server also
  // revokes tokens already issued from that code, since a replay means the
  // code leaked.
  if (consumedCodes.has(code)) {
    return tokenError("invalid_grant", "Authorization code has already been used");
  }
  consumedCodes.add(code);

  // ── 3. ...and issued to THIS client for THIS redirect_uri. ──────────────
  if (codePayload.clientId !== clientId || clientId !== REGISTERED_CLIENT_ID) {
    return tokenError("invalid_grant", "client_id does not match the authorization code");
  }
  if (codePayload.redirectUri !== redirectUri) {
    return tokenError("invalid_grant", "redirect_uri does not match the authorization request");
  }

  // ── 4. THE PKCE CHECK (RFC 7636 §4.6) ───────────────────────────────────
  // Hash the verifier the client just sent; it must equal the challenge the
  // client sent at the START of the flow (which we sealed inside the code).
  // Only the app instance that generated the verifier can pass this — a
  // thief holding a stolen code cannot.
  const expectedChallenge = await computeS256Challenge(codeVerifier);
  if (expectedChallenge !== codePayload.codeChallenge) {
    return tokenError("invalid_grant", "PKCE verification failed: code_verifier does not match code_challenge");
  }

  // ── All checks passed → issue the access token (flow step 7). ──────────
  const expiresInSeconds = 3600;
  const tokenPayload: AccessTokenPayload = {
    kind: "access_token",
    sub: codePayload.sub,
    clientId,
    scope: codePayload.scope,
    expiresAt: Date.now() + expiresInSeconds * 1000,
  };
  const accessToken = await signPayload(tokenPayload);

  // Success response shape per §5.1. Cache-Control: no-store is required —
  // nothing on the path may cache a token response.
  return Response.json(
    {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: expiresInSeconds,
      scope: codePayload.scope,
    },
    { headers: { "cache-control": "no-store" } },
  );
}

/** Error response shape per RFC 6749 §5.2: HTTP 400 + {error, error_description}. */
function tokenError(error: string, description: string): Response {
  return Response.json(
    { error, error_description: description },
    { status: 400, headers: { "cache-control": "no-store" } },
  );
}
