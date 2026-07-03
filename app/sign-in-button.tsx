"use client";

/**
 * Flow steps 1–2: start the login.
 *
 * "use client" because this must run in the browser: the whole point of
 * PKCE is that the code_verifier is generated ON the device and never
 * leaves it (except inside the final, direct token request).
 */

import { oauthConfig, storageKeys } from "@/lib/oauth-config";
import { createCodeChallenge, createCodeVerifier, createState } from "@/lib/pkce";

async function startLogin() {
  // Step 1: per-login secrets, kept in this tab only.
  const codeVerifier = createCodeVerifier();
  const state = createState();

  // We are about to leave the page (full redirect), so persist them in
  // sessionStorage for the /callback page to pick up when we come back.
  sessionStorage.setItem(storageKeys.codeVerifier, codeVerifier);
  sessionStorage.setItem(storageKeys.state, state);

  // Step 2: send the provider the HASH of the verifier, never the verifier.
  const codeChallenge = await createCodeChallenge(codeVerifier);

  const authorizeUrl = new URL(oauthConfig.authorizationEndpoint, window.location.origin);
  authorizeUrl.searchParams.set("response_type", "code"); // "give me an authorization code"
  authorizeUrl.searchParams.set("client_id", oauthConfig.clientId);
  authorizeUrl.searchParams.set("redirect_uri", `${window.location.origin}${oauthConfig.redirectPath}`);
  authorizeUrl.searchParams.set("scope", oauthConfig.scope);
  authorizeUrl.searchParams.set("state", state);
  authorizeUrl.searchParams.set("code_challenge", codeChallenge);
  authorizeUrl.searchParams.set("code_challenge_method", "S256");

  // Full-page navigation, not fetch: the user has to actually see and
  // interact with the provider's login/consent UI.
  window.location.assign(authorizeUrl.toString());
}

export function SignInButton() {
  return (
    <button className="primary" onClick={() => void startLogin()}>
      Sign in with Mock Provider
    </button>
  );
}
