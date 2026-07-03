/**
 * SDK (public client) configuration.
 *
 * In a real integration these values ship inside the partner's app bundle.
 * Note what is here and what is not:
 *
 * - `clientKey` — a PUBLIC credential. It identifies the app and initiates
 *   sign-in, but it is never the security boundary: a valid partner vouch
 *   (anchored on the confidential server-key, which lives only on the
 *   partner backend — see app/partner/session/route.ts) is always required.
 * - No client_secret, and no server-key. Nothing confidential can live in
 *   code that ships to a device.
 */
export const sdkConfig = {
  clientKey: "ck-demo-acme-app",

  /** The partner's OWN backend endpoint that vouches for the member. */
  partnerSessionEndpoint: "/partner/session",

  /** Token Exchange Service endpoints. */
  tokenEndpoint: "/tes/token",
  refreshEndpoint: "/tes/token/refresh",
  revokeEndpoint: "/tes/revoke",

  /** A protected member endpoint (stands in for the real member APIs). */
  memberProfileEndpoint: "/pager/member-profile",
} as const;

/**
 * Demo members, identified by the PARTNER's own external member id — the
 * identity model of this flow: the partner keeps using its own ids, and the
 * Token Exchange Service resolves them to internal identities at mint time.
 */
export const demoMembers = {
  provisioned: "ada@acme",
  notProvisioned: "walt@acme",
} as const;
