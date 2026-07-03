/**
 * A PROTECTED MEMBER ENDPOINT (flow step 6).
 *
 * This stands in for the real member APIs (chat, appointments, uploads...).
 * The point it demonstrates: a downstream service does NOT call the TES to
 * authorize a request. It verifies the token locally — signature, expiry,
 * audience — because the token is self-describing: issuer, member,
 * organization and scope are all claims inside it. (In production the
 * services verify against the TES's published JWKS public keys; accepting
 * the new issuer is additive — existing auth keeps working next to it.)
 *
 * The one non-local check is the revocation set — the deliberate trade-off
 * that makes logout real. Production systems bound this cost (shared
 * cache, or checking revocation only for refresh) — the demo checks inline.
 */

import {
  AccessTokenPayload,
  MEMBER_API_AUDIENCE,
  MEMBER_PROFILE,
  TES_ISSUER,
  revokedSessionIds,
  verifyPayload,
} from "@/lib/tes.server";

export async function GET(request: Request): Promise<Response> {
  const authorization = request.headers.get("authorization") ?? "";
  const [scheme, token] = authorization.split(" ");
  if (scheme !== "Bearer" || !token) {
    return unauthorized("Missing Bearer token");
  }

  const payload = await verifyPayload<AccessTokenPayload>(token);
  if (!payload || payload.kind !== "access_token") {
    return unauthorized("Access token is invalid or expired");
  }
  // `iss`/`aud` checks: a token minted by someone else, or minted for a
  // different API, does not work here even if its signature verifies.
  if (payload.iss !== TES_ISSUER || payload.aud !== MEMBER_API_AUDIENCE) {
    return unauthorized("Token was not issued for this API");
  }
  if (revokedSessionIds.has(payload.jti)) {
    return unauthorized("Session has been revoked");
  }

  const member = MEMBER_PROFILE[payload.organization]?.[payload.clientExternalId];
  if (!member) {
    return unauthorized("Member no longer exists");
  }

  return Response.json({
    sub: payload.sub,
    name: member.name,
    email: member.email,
    organization: payload.organization,
    scope: payload.scope,
  });
}

function unauthorized(description: string): Response {
  // RFC 6750 §3: challenge the client via WWW-Authenticate on 401s.
  return Response.json(
    { error: "invalid_token", error_description: description },
    {
      status: 401,
      headers: { "www-authenticate": `Bearer error="invalid_token", error_description="${description}"` },
    },
  );
}
