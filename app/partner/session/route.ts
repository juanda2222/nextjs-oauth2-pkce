/**
 * PARTNER BACKEND — "start a session" endpoint (flow step 2→4 relay).
 *
 * This file plays a DIFFERENT ACTOR than app/tes/*: it is the partner's own
 * backend, the code an integrating partner writes (kept in this repo so the
 * whole flow runs locally). It exists for exactly one reason: it is the
 * only place the confidential SERVER-KEY may live. The key never ships in
 * app code; this backend uses it to vouch for members it has already
 * authenticated by its own means (its session cookie, etc.).
 *
 * Note the strict information diet:
 *   - receives: the member id + the PKCE code_challenge (a hash),
 *   - relays the challenge verbatim to the TES — it never sees the
 *     code_verifier, so even the partner backend cannot redeem the code
 *     it hands back,
 *   - returns: the one-time code, in the response body (no redirect).
 */

import { oauthError } from "@/lib/tes.server";

/**
 * The confidential machine-to-machine credential, bound to org-acme. In
 * production: an env var / secrets manager on the partner's servers.
 */
const SERVER_KEY = process.env.PARTNER_SERVER_KEY ?? "sk-demo-acme-SERVER-SIDE-ONLY";

export async function POST(request: Request): Promise<Response> {
  let body: { memberId?: string; codeChallenge?: string };
  try {
    body = await request.json();
  } catch {
    return oauthError(400, "invalid_request", "Body must be JSON");
  }
  const { memberId, codeChallenge } = body;
  if (!memberId || !codeChallenge) {
    return oauthError(400, "invalid_request", "memberId and codeChallenge are required");
  }

  // A real partner backend authenticates ITS OWN user here (session cookie,
  // etc.) and derives memberId from that session — it must never vouch for
  // an id the caller merely claims. The demo trusts the field so the flow
  // is runnable; this is the one shortcut that would be a vulnerability in
  // production, which is why it gets the loudest comment in the file.

  // Vouch: one authenticated server-to-server call. The partner needs no
  // cryptography of its own — trust is anchored on the server-key.
  const tesResponse = await fetch(new URL("/tes/authorize", request.url), {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${SERVER_KEY}`,
    },
    body: JSON.stringify({ platform_member_id: memberId, code_challenge: codeChallenge }),
  });

  // Relay the TES verdict (the code, or e.g. 409 member_not_provisioned)
  // straight through to the app.
  return Response.json(await tesResponse.json(), {
    status: tesResponse.status,
    headers: { "cache-control": "no-store" },
  });
}
