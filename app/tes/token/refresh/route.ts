/**
 * TES — /tes/token/refresh: keep the session alive without re-sign-in.
 *
 * Access tokens are deliberately short-lived (minutes); the refresh token
 * is how the app outlives them. Two properties worth studying:
 *
 * ROTATION — every refresh retires the old pair (its session id goes into
 * the revoked set) and mints a fresh pair with a NEW session id. A refresh
 * token works exactly once. If a stolen refresh token is replayed after
 * the legitimate app already rotated it, the request fails — and that
 * failure is itself a theft signal a real TES would alert on.
 *
 * RE-RESOLUTION — identity is looked up again at refresh time, not copied
 * blindly from the old token. If the member was deprovisioned or their
 * claims changed, the change propagates within one access-token lifetime,
 * without re-sign-in.
 */

import {
  ACCESS_TOKEN_TTL_SECONDS,
  MEMBER_PROFILE,
  RefreshTokenPayload,
  mintTokenPair,
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

  if (body.get("grant_type") !== "refresh_token") {
    return oauthError(400, "unsupported_grant_type", "Only refresh_token is supported here");
  }
  const refreshToken = body.get("refresh_token");
  if (!refreshToken) {
    return oauthError(400, "invalid_request", "refresh_token is required");
  }

  const payload = await verifyPayload<RefreshTokenPayload>(refreshToken);
  if (!payload || payload.kind !== "refresh_token") {
    return oauthError(400, "invalid_grant", "Refresh token is invalid or expired");
  }
  if (revokedSessionIds.has(payload.jti)) {
    return oauthError(400, "invalid_grant", "Refresh token has been rotated or revoked");
  }

  // Re-resolve identity (see header). Deprovisioned member → session over.
  const member = MEMBER_PROFILE[payload.organization]?.[payload.clientExternalId];
  if (!member) {
    return oauthError(400, "invalid_grant", "Member is no longer provisioned");
  }

  // Rotate: kill the old session id (this invalidates the old refresh token
  // AND its matching access token), then mint a fresh pair.
  revokedSessionIds.add(payload.jti);
  const { accessToken, refreshToken: newRefreshToken } = await mintTokenPair({
    sub: member.sub,
    clientExternalId: payload.clientExternalId,
    organization: payload.organization,
    scope: payload.scope,
  });

  return Response.json(
    {
      access_token: accessToken,
      refresh_token: newRefreshToken,
      token_type: "Bearer",
      expires_in: ACCESS_TOKEN_TTL_SECONDS,
      scope: payload.scope,
    },
    { headers: { "cache-control": "no-store" } },
  );
}
