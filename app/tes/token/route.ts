/**
 * TES — /tes/token: exchange the one-time code for a member token (step 5).
 *
 * Called directly by the APP (the public client), not by the partner
 * backend. This is where PKCE pays off — the ONE comparison that matters is
 * the hash check below. Note this is a direct HTTPS fetch: the verifier is
 * revealed exactly once, here, and never touched the partner backend.
 */

import {
  ACCESS_TOKEN_TTL_SECONDS,
  OneTimeCodePayload,
  REGISTERED_CLIENT_KEYS,
  computeS256Challenge,
  consumedCodes,
  mintTokenPair,
  oauthError,
  verifyPayload,
} from "@/lib/tes.server";

export async function POST(request: Request): Promise<Response> {
  // OAuth token endpoints take a form-encoded body (RFC 6749 §3.2), not JSON.
  const contentType = request.headers.get("content-type") ?? "";
  if (!contentType.includes("application/x-www-form-urlencoded")) {
    return oauthError(400, "invalid_request", "Body must be application/x-www-form-urlencoded");
  }
  const body = new URLSearchParams(await request.text());

  const grantType = body.get("grant_type");
  const code = body.get("code");
  const codeVerifier = body.get("code_verifier");
  const clientKey = body.get("client_id");

  if (grantType !== "authorization_code") {
    return oauthError(400, "unsupported_grant_type", "Only authorization_code is supported here (refresh lives at /tes/token/refresh)");
  }
  if (!code || !codeVerifier || !clientKey) {
    return oauthError(400, "invalid_request", "code, code_verifier and client_id are required");
  }
  // The client-key is public; it identifies the app but proves nothing —
  // the real security checks are the code's signature and the PKCE match.
  if (!REGISTERED_CLIENT_KEYS.has(clientKey)) {
    return oauthError(400, "invalid_client", "Unknown client_id");
  }

  // ── 1. The code must be one the TES minted, and unexpired... ───────────
  const codePayload = await verifyPayload<OneTimeCodePayload>(code);
  if (!codePayload || codePayload.kind !== "one_time_code") {
    return oauthError(400, "invalid_grant", "One-time code is invalid or expired");
  }

  // ── 2. ...never redeemed before... ─────────────────────────────────────
  // Single-use, burned on first presentation: a replay means the code
  // leaked somewhere between the partner backend and the app.
  if (consumedCodes.has(code)) {
    return oauthError(400, "invalid_grant", "One-time code has already been used");
  }
  consumedCodes.add(code);

  // ── 3. THE PKCE CHECK (RFC 7636 §4.6) ───────────────────────────────────
  // Hash the verifier the app just sent; it must equal the challenge the
  // app generated at the very start — which reached us through the partner
  // backend, sealed inside the code. Only the app instance holding the
  // original verifier can pass this. The partner backend, which handled
  // the code, cannot: it only ever saw the hash.
  const expectedChallenge = await computeS256Challenge(codeVerifier);
  if (expectedChallenge !== codePayload.codeChallenge) {
    return oauthError(400, "invalid_grant", "PKCE verification failed: code_verifier does not match code_challenge");
  }

  // ── All checks passed → mint the member token pair (flow step 5). ──────
  // Identity was already resolved at /tes/authorize; the code carries it.
  const { accessToken, refreshToken } = await mintTokenPair({
    sub: codePayload.sub,
    clientExternalId: codePayload.clientExternalId,
    organization: codePayload.organization,
    scope: codePayload.scope,
  });

  // Success shape per RFC 6749 §5.1; no-store because token responses must
  // never be cached anywhere on the path.
  return Response.json(
    {
      access_token: accessToken,
      refresh_token: refreshToken,
      token_type: "Bearer",
      expires_in: ACCESS_TOKEN_TTL_SECONDS,
      scope: codePayload.scope,
    },
    { headers: { "cache-control": "no-store" } },
  );
}
