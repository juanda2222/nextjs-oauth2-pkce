/**
 * MOCK PROVIDER — Authorization endpoint (RFC 6749 §3.1 + RFC 7636 §4.3).
 *
 * Flow step 3: the user lands here via a full-page redirect from the app,
 * carrying the PKCE `code_challenge`. A real provider would show its own
 * login form (enter password, MFA...) and a consent screen; we skip straight
 * to a consent screen for a hardcoded demo user.
 *
 * On "Allow", flow step 4: we mint a short-lived, single-purpose
 * authorization code that has the code_challenge sealed inside it, and
 * redirect the browser back to the app's redirect_uri.
 */

import {
  AuthorizationCodePayload,
  DEMO_USER,
  REGISTERED_CLIENT_ID,
  signPayload,
} from "@/lib/provider";

export async function GET(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const params = url.searchParams;

  const responseType = params.get("response_type");
  const clientId = params.get("client_id");
  const redirectUri = params.get("redirect_uri");
  const state = params.get("state");
  const codeChallenge = params.get("code_challenge");
  const codeChallengeMethod = params.get("code_challenge_method");
  const scope = params.get("scope") ?? "";
  const decision = params.get("decision"); // set when the consent form submits back here

  // ── Validate the request ────────────────────────────────────────────────
  // A real provider validates client_id and redirect_uri against what was
  // registered in its dashboard, with EXACT string matching — a lax
  // redirect_uri check lets attackers redirect codes to themselves.
  // Our "registry" is: one known client, and the redirect_uri must be this
  // same origin's /callback page.

  if (clientId !== REGISTERED_CLIENT_ID) {
    return textError(400, `Unknown client_id "${clientId}".`);
  }
  if (redirectUri !== `${url.origin}/callback`) {
    return textError(400, `redirect_uri "${redirectUri}" is not registered for this client.`);
  }

  // From here on the redirect_uri is trusted, so per RFC 6749 §4.1.2.1
  // remaining errors are reported by redirecting back to the app.
  if (responseType !== "code") {
    return redirectWithError(redirectUri, state, "unsupported_response_type");
  }
  if (!codeChallenge) {
    // A provider that *requires* PKCE (like this one — and like OAuth 2.1)
    // rejects requests without a challenge.
    return redirectWithError(redirectUri, state, "invalid_request", "code_challenge is required");
  }
  if (codeChallengeMethod !== "S256") {
    return redirectWithError(redirectUri, state, "invalid_request", "only code_challenge_method=S256 is supported");
  }

  // ── No decision yet → show the consent screen ───────────────────────────
  if (decision === null) {
    return consentScreen(params, scope);
  }

  // ── User denied → standard error redirect (§4.1.2.1) ───────────────────
  if (decision !== "allow") {
    return redirectWithError(redirectUri, state, "access_denied", "The user denied the request");
  }

  // ── User approved → mint the authorization code (flow step 4) ──────────
  const codePayload: AuthorizationCodePayload = {
    kind: "authorization_code",
    sub: DEMO_USER.sub,
    clientId,
    redirectUri,
    codeChallenge, // sealed in: the token endpoint will check the verifier against this
    scope,
    expiresAt: Date.now() + 60_000, // codes are single-use and short-lived (§4.1.2 recommends ≤10 min)
  };
  const code = await signPayload(codePayload);

  const callback = new URL(redirectUri);
  callback.searchParams.set("code", code);
  if (state !== null) callback.searchParams.set("state", state); // echoed back untouched
  return Response.redirect(callback.toString(), 302);
}

// ── Helpers ───────────────────────────────────────────────────────────────

function textError(status: number, message: string): Response {
  return new Response(message, { status, headers: { "content-type": "text/plain" } });
}

function redirectWithError(
  redirectUri: string,
  state: string | null,
  error: string,
  description?: string,
): Response {
  const target = new URL(redirectUri);
  target.searchParams.set("error", error);
  if (description) target.searchParams.set("error_description", description);
  if (state !== null) target.searchParams.set("state", state);
  return Response.redirect(target.toString(), 302);
}

/**
 * A minimal consent screen. The Allow/Deny buttons submit right back to this
 * endpoint with all original parameters plus `decision`.
 */
function consentScreen(originalParams: URLSearchParams, scope: string): Response {
  // Re-emit every original query param as a hidden input, HTML-escaped.
  const hiddenInputs = [...originalParams.entries()]
    .map(
      ([name, value]) =>
        `<input type="hidden" name="${escapeHtml(name)}" value="${escapeHtml(value)}">`,
    )
    .join("\n        ");

  const scopeList = scope
    .split(" ")
    .filter(Boolean)
    .map((item) => `<li><code>${escapeHtml(item)}</code></li>`)
    .join("");

  const html = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Mock Provider — Sign in</title>
    <style>
      body { font-family: system-ui, sans-serif; background: #1a1d23; color: #e8e8e8;
             display: grid; place-items: center; min-height: 100vh; margin: 0; }
      .card { background: #23272f; border: 1px solid #3a3f4a; border-radius: 12px;
              padding: 2rem; max-width: 26rem; }
      .badge { color: #f0a500; font-size: 0.8rem; letter-spacing: 0.08em; }
      button { font-size: 1rem; padding: 0.6rem 1.4rem; border-radius: 8px;
               border: 1px solid transparent; cursor: pointer; margin-right: 0.5rem; }
      .allow { background: #2e7d32; color: white; }
      .deny  { background: transparent; color: #e8e8e8; border-color: #3a3f4a; }
      code { color: #8ab4f8; }
    </style>
  </head>
  <body>
    <div class="card">
      <p class="badge">MOCK AUTHORIZATION SERVER</p>
      <h1>Sign in as Ada Lovelace?</h1>
      <p>
        A real provider would ask for your password here. This demo signs you
        in as a hardcoded user.
      </p>
      <p><strong>demo-public-client</strong> is asking for:</p>
      <ul>${scopeList}</ul>
      <form method="GET" action="/oauth/authorize">
        ${hiddenInputs}
        <button class="allow" name="decision" value="allow">Allow</button>
        <button class="deny" name="decision" value="deny">Deny</button>
      </form>
    </div>
  </body>
</html>`;

  return new Response(html, { headers: { "content-type": "text/html; charset=utf-8" } });
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
