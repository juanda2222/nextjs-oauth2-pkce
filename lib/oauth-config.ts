/**
 * OAuth client configuration.
 *
 * With a real provider (Google, Auth0, Okta...) you would get these values
 * by registering your app in their dashboard, and the endpoints would live
 * on the provider's domain. Here they point at the mock provider that ships
 * inside this repo (see app/oauth/*), so the demo works out of the box.
 *
 * Note what is NOT here: a client secret. This is a *public client* — the
 * code runs in the browser where nothing can be kept secret. PKCE is exactly
 * the mechanism that makes the code exchange safe without one.
 */
export const oauthConfig = {
  clientId: "demo-public-client",
  authorizationEndpoint: "/oauth/authorize",
  tokenEndpoint: "/oauth/token",
  userInfoEndpoint: "/oauth/userinfo",
  redirectPath: "/callback",
  scope: "openid profile email",
} as const;

/**
 * Keys used to stash the per-login values in sessionStorage between the
 * redirect to the provider and the redirect back to /callback.
 *
 * sessionStorage (rather than localStorage) because these values are only
 * meaningful for the current login attempt in the current tab, and they
 * should not outlive it.
 */
export const storageKeys = {
  codeVerifier: "pkce_code_verifier",
  state: "oauth_state",
} as const;
