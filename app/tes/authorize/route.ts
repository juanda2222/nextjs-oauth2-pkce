/**
 * TES — /tes/authorize: the partner VOUCHES for a member (flow step 3).
 *
 * This is where this flow departs from the textbook redirect flow. There is
 * no browser here, no login form, no consent screen, no redirect_uri: the
 * member already authenticated with the PARTNER'S own app. Instead, the
 * partner's BACKEND calls this endpoint machine-to-machine, authenticated
 * with its confidential server-key, and says "start a session for member X;
 * here is the PKCE challenge their app generated".
 *
 * The TES's authorization decision is therefore not "did the user log in
 * and consent?" but:
 *   1. Is this a real partner? (valid server-key)
 *   2. Does this partner OWN this member? (registry lookup scoped to the
 *      key's own organization — tenant isolation by construction)
 *   3. Was the member provisioned ahead of time?
 *
 * If yes, it mints a short-lived, single-use one-time code with the PKCE
 * challenge sealed inside, and returns it IN THE RESPONSE BODY — the code
 * never rides a URL, which is why this flow has no `state` parameter and no
 * redirect_uri validation: the attack surface those defend simply does not
 * exist here.
 */

import {
  MEMBER_PROFILE,
  ONE_TIME_CODE_TTL_SECONDS,
  OneTimeCodePayload,
  PARTNERS_BY_SERVER_KEY,
  oauthError,
  signPayload,
} from "@/lib/tes.server";

export async function POST(request: Request): Promise<Response> {
  // ── 1. Authenticate the PARTNER (not a user) ────────────────────────────
  const authorization = request.headers.get("authorization") ?? "";
  const [scheme, serverKey] = authorization.split(" ");
  const partner = scheme === "Bearer" && serverKey ? PARTNERS_BY_SERVER_KEY[serverKey] : undefined;
  if (!partner) {
    return oauthError(401, "invalid_client", "Unknown or missing server-key");
  }

  let body: { platform_member_id?: string; code_challenge?: string };
  try {
    body = await request.json();
  } catch {
    return oauthError(400, "invalid_request", "Body must be JSON");
  }
  const { platform_member_id: platformMemberId, code_challenge: codeChallenge } = body;

  if (!platformMemberId || !codeChallenge) {
    return oauthError(400, "invalid_request", "platform_member_id and code_challenge are required");
  }
  // A base64url SHA-256 digest is exactly 43 chars; anything else means the
  // app hashed wrong (or sent the raw verifier — reject, never store it).
  if (!/^[A-Za-z0-9_-]{43}$/.test(codeChallenge)) {
    return oauthError(400, "invalid_request", "code_challenge must be a base64url-encoded SHA-256 digest");
  }

  // ── 2 + 3. Resolve the member INSIDE the partner's own organization ────
  // The lookup is scoped to the organization bound to the server-key, so a
  // partner asking about another tenant's member gets the same answer as
  // for a nonexistent one — it cannot even probe whether the member exists.
  const member = MEMBER_PROFILE[partner.organization]?.[platformMemberId];
  if (!member) {
    // Provision-before-sign-in is the rule: the partner backend creates its
    // members ahead of time; sign-in never creates them. The distinct 409
    // (vs a generic 400) lets the partner branch on it: provision, retry.
    return oauthError(409, "member_not_provisioned", "Member is not provisioned; provision it and retry");
  }

  // ── Mint the one-time code (flow step 4) ────────────────────────────────
  const codePayload: OneTimeCodePayload = {
    kind: "one_time_code",
    sub: member.sub,
    clientExternalId: platformMemberId,
    organization: partner.organization,
    codeChallenge, // sealed in: /tes/token checks the verifier against this
    scope: "member",
    expiresAt: Date.now() + ONE_TIME_CODE_TTL_SECONDS * 1000,
  };

  return Response.json(
    { code: await signPayload(codePayload), expires_in: ONE_TIME_CODE_TTL_SECONDS },
    { headers: { "cache-control": "no-store" } },
  );
}
