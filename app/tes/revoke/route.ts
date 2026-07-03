/**
 * TES — /tes/revoke: logout, done properly (RFC 7009 shape).
 *
 * This endpoint is the payoff of OWNING the issuer. With a stateless
 * third-party issuer, "logout" is a client-side fiction: the app forgets
 * the token, but the token itself keeps working until it expires. Here the
 * session id goes into a server-side revocation set that every verifier
 * checks, so the access token and the refresh token both die NOW.
 */

import {
  RefreshTokenPayload,
  oauthError,
  revokedSessionIds,
  verifyPayload,
} from "@/lib/tes.server";

export async function POST(request: Request): Promise<Response> {
  const contentType = request.headers.get("content-type") ?? "";
  if (!contentType.includes("application/x-www-form-urlencoded")) {
    return oauthError(400, "invalid_request", "Body must be application/x-www-form-urlencoded");
  }
  const body = new URLSearchParams(await request.text());
  const token = body.get("token");
  if (!token) {
    return oauthError(400, "invalid_request", "token is required");
  }

  // The access and refresh token share one session id, so revoking by the
  // refresh token kills the whole session at once.
  const payload = await verifyPayload<RefreshTokenPayload>(token);
  if (payload?.kind === "refresh_token") {
    revokedSessionIds.add(payload.jti);
  }

  // RFC 7009 §2.2: respond 200 even for an invalid/unknown token — the
  // caller's goal ("this token should not work") is already true, and a
  // distinct error would let attackers probe which tokens are live.
  return Response.json({ revoked: true }, { headers: { "cache-control": "no-store" } });
}
