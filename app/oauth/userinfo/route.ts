/**
 * MOCK PROVIDER — UserInfo endpoint.
 *
 * Flow step 8: a protected resource. The app proves it is allowed to read
 * the user's profile by presenting the access token as a Bearer token
 * (RFC 6750): `Authorization: Bearer <token>`.
 *
 * This mirrors OpenID Connect's /userinfo endpoint — the "who just logged
 * in?" API that real providers expose.
 */

import { AccessTokenPayload, DEMO_USER, verifyPayload } from "@/lib/provider";

export async function GET(request: Request): Promise<Response> {
  const authorization = request.headers.get("authorization") ?? "";
  const [scheme, token] = authorization.split(" ");

  if (scheme !== "Bearer" || !token) {
    // RFC 6750 §3: challenge the client with WWW-Authenticate on 401s.
    return unauthorized("Missing Bearer token");
  }

  const payload = await verifyPayload<AccessTokenPayload>(token);
  if (!payload || payload.kind !== "access_token") {
    return unauthorized("Access token is invalid or expired");
  }

  // A real endpoint would also check the token's scope covers what is being
  // asked for (e.g. require "profile" here).
  return Response.json({
    sub: payload.sub,
    name: DEMO_USER.name,
    email: DEMO_USER.email,
    scope: payload.scope,
  });
}

function unauthorized(description: string): Response {
  return Response.json(
    { error: "invalid_token", error_description: description },
    {
      status: 401,
      headers: { "www-authenticate": `Bearer error="invalid_token", error_description="${description}"` },
    },
  );
}
