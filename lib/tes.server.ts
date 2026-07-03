/**
 * The MOCK Token Exchange Service (TES) — data, crypto, and token shapes.
 *
 * ─────────────────────────────────────────────────────────────────────────
 * The TES is the single authority for member tokens. It plays the role a
 * hosted identity provider would otherwise play, but it lives INSIDE the
 * platform, next to the member registry, so:
 *   - member resolution happens next to the data it needs,
 *   - the platform fully controls the token's shape and lifetime,
 *   - logout/revocation are first-class (a stateless external issuer
 *     cannot invalidate a token server-side).
 * Its endpoints live under app/tes/*.
 * ─────────────────────────────────────────────────────────────────────────
 *
 * A real TES keeps its registries and issued-token state in databases. To
 * keep this demo dependency-free, registries are in-code constants and the
 * codes/tokens are *self-describing*: a JSON payload plus an HMAC-SHA256
 * signature, both base64url-encoded, joined by a dot:
 *
 *     base64url(payload-json) + "." + base64url(hmac-signature)
 *
 * Only someone who knows the signing secret can produce a valid signature.
 * (If this shape reminds you of a JWT — yes, a JWT is this same idea with
 * an extra header. A real TES signs asymmetrically instead — RS256/ES256 —
 * and publishes the PUBLIC keys at /.well-known/jwks.json so the ~30
 * downstream member services can verify tokens without sharing a secret.)
 */

import { base64UrlToString, bytesToBase64Url, stringToBase64Url } from "./base64url.shared";

/**
 * Guard for the `.server.ts` naming convention: this module holds the signing
 * secret and the partner server-keys, so it must never be bundled into
 * browser JavaScript. If an import from a client component ever drags it in,
 * fail loudly instead of shipping the secrets. (With libraries allowed you'd
 * `import "server-only"` and Next.js would catch this at build time.)
 */
if (typeof window !== "undefined") {
  throw new Error("lib/tes.server.ts was imported into browser code — it must stay on the server.");
}

/**
 * Demo-only signing secret. A real TES keeps its private keys in a secrets
 * manager and rotates them. If it leaks, anyone can mint valid tokens.
 */
const SIGNING_SECRET =
  process.env.TES_SIGNING_SECRET ?? "demo-only-secret-never-do-this-in-production";

/** Stamped into every token so verifiers know who minted it (`iss`). */
export const TES_ISSUER = "demo-token-exchange-service";

/** Who the access token is FOR (`aud`) — the member-API surface. */
export const MEMBER_API_AUDIENCE = "member-api";

export const ACCESS_TOKEN_TTL_SECONDS = 15 * 60; // short-lived by design
export const REFRESH_TOKEN_TTL_SECONDS = 30 * 24 * 3600;
export const ONE_TIME_CODE_TTL_SECONDS = 60; // single-use and ~60s

// ─── Registries (real TES: database rows, not constants) ──────────────────

/**
 * Partner registry: server-key → partner organization.
 *
 * The server-key is the CONFIDENTIAL machine-to-machine credential; it lives
 * only on the partner's backend. Because each key is bound to exactly one
 * organization, a partner can only vouch for ITS OWN members — cross-tenant
 * access is impossible by construction, there is no code path for it.
 *
 * (In production this would be a real M2M OAuth client per partner; a static
 * bearer key keeps the demo readable.)
 */
export const PARTNERS_BY_SERVER_KEY: Record<string, { partnerId: string; organization: string }> = {
  "sk-demo-acme-SERVER-SIDE-ONLY": { partnerId: "acme", organization: "org-acme" },
  "sk-demo-globex-SERVER-SIDE-ONLY": { partnerId: "globex", organization: "org-globex" },
};

/** Registered public client-keys (the app-side credential). */
export const REGISTERED_CLIENT_KEYS = new Set(["ck-demo-acme-app", "ck-demo-globex-app"]);

/**
 * The member registry ("member-profile"): organization → the partner's own
 * EXTERNAL member id → internal identity.
 *
 * This is the identity model: partners keep using their own ids everywhere;
 * the TES resolves them to internal identities at mint time and stamps both
 * into the token. Onboarding a member = inserting a row here ("provisioning"),
 * which the partner backend does ahead of sign-in. Onboarding a partner =
 * a server-key row above plus member rows here: data, not infrastructure.
 */
export const MEMBER_PROFILE: Record<string, Record<string, { sub: string; name: string; email: string }>> = {
  "org-acme": {
    "ada@acme": { sub: "member-42", name: "Ada Lovelace", email: "ada@example.com" },
    // "walt@acme" is intentionally ABSENT: he exists at the partner but was
    // never provisioned. Signing him in demonstrates the member_not_provisioned
    // path. Note: MEMBER_PROFILE["org-globex"] knows nothing about acme's
    // members, and vice versa — that is the tenant isolation.
  },
  "org-globex": {
    "grace@globex": { sub: "member-77", name: "Grace Hopper", email: "grace@example.com" },
  },
};

// ─── Issued-token state (real TES: database; here: per-process memory) ─────

/**
 * One-time codes already redeemed, and sessions killed by rotation/revoke.
 * In-memory Sets reset on server restart and would not work across multiple
 * instances — fine for a demo, and a useful reminder that revocation is
 * exactly the part of a token system that NEEDS shared state.
 */
export const consumedCodes = new Set<string>();
export const revokedSessionIds = new Set<string>();

// ─── Signing / verifying (web-standard crypto only) ────────────────────────

async function getSigningKey(): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(SIGNING_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

/** Serialize + sign a payload. Used to mint codes, access and refresh tokens. */
export async function signPayload(payload: object): Promise<string> {
  const encodedPayload = stringToBase64Url(JSON.stringify(payload));
  const key = await getSigningKey();
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(encodedPayload),
  );
  return `${encodedPayload}.${bytesToBase64Url(new Uint8Array(signature))}`;
}

/**
 * Verify signature + expiry and return the payload, or null if anything is
 * off. `crypto.subtle.verify` does a constant-time comparison — comparing
 * signatures with `===` would leak information through timing differences.
 */
export async function verifyPayload<T extends { expiresAt: number }>(
  token: string,
): Promise<T | null> {
  const [encodedPayload, encodedSignature] = token.split(".");
  if (!encodedPayload || !encodedSignature) return null;

  let signatureBytes: Uint8Array<ArrayBuffer>;
  try {
    const binary = atob(encodedSignature.replace(/-/g, "+").replace(/_/g, "/"));
    signatureBytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      signatureBytes[i] = binary.charCodeAt(i);
    }
  } catch {
    return null;
  }

  const key = await getSigningKey();
  const isValid = await crypto.subtle.verify(
    "HMAC",
    key,
    signatureBytes,
    new TextEncoder().encode(encodedPayload),
  );
  if (!isValid) return null;

  let payload: T;
  try {
    payload = JSON.parse(base64UrlToString(encodedPayload));
  } catch {
    return null;
  }

  if (typeof payload.expiresAt !== "number" || Date.now() > payload.expiresAt) {
    return null; // expired
  }
  return payload;
}

/**
 * The TES side of PKCE: hash the verifier the same way the app did (S256)
 * so the token endpoint can compare it against the challenge that arrived —
 * via the partner backend — at the start of the flow.
 */
export async function computeS256Challenge(codeVerifier: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(codeVerifier),
  );
  return bytesToBase64Url(new Uint8Array(digest));
}

// ─── Payload shapes ────────────────────────────────────────────────────────

/**
 * The one-time code minted at /tes/authorize. It seals in everything /tes/token
 * needs to finish the job: WHO was vouched for (already resolved to an
 * internal identity), by WHICH organization, and the PKCE challenge that
 * binds redemption to one app instance.
 */
export type OneTimeCodePayload = {
  kind: "one_time_code";
  sub: string;
  clientExternalId: string;
  organization: string;
  codeChallenge: string;
  scope: string;
  expiresAt: number;
};

/**
 * Access-token claims, mirroring standard JWT claims: iss (who minted it),
 * sub (the member), aud (which API it is for), plus the organization so
 * every request is self-describing, and jti (a unique token/session id —
 * what makes refresh rotation and server-side revocation possible).
 */
export type AccessTokenPayload = {
  kind: "access_token";
  iss: string;
  sub: string;
  aud: string;
  organization: string;
  clientExternalId: string;
  scope: string;
  jti: string;
  expiresAt: number;
};

/** Refresh-token payload. Shares the session `jti` with its access token. */
export type RefreshTokenPayload = {
  kind: "refresh_token";
  sub: string;
  organization: string;
  clientExternalId: string;
  scope: string;
  jti: string;
  expiresAt: number;
};

/**
 * Mint a matched access + refresh pair. Both carry the same session id
 * (`jti`), so revoking the session kills both at once, and a refresh
 * rotation retires the whole old pair.
 */
export async function mintTokenPair(member: {
  sub: string;
  clientExternalId: string;
  organization: string;
  scope: string;
}): Promise<{ accessToken: string; refreshToken: string; sessionId: string }> {
  const sessionId = crypto.randomUUID();

  const accessPayload: AccessTokenPayload = {
    kind: "access_token",
    iss: TES_ISSUER,
    sub: member.sub,
    aud: MEMBER_API_AUDIENCE,
    organization: member.organization,
    clientExternalId: member.clientExternalId,
    scope: member.scope,
    jti: sessionId,
    expiresAt: Date.now() + ACCESS_TOKEN_TTL_SECONDS * 1000,
  };
  const refreshPayload: RefreshTokenPayload = {
    kind: "refresh_token",
    sub: member.sub,
    organization: member.organization,
    clientExternalId: member.clientExternalId,
    scope: member.scope,
    jti: sessionId,
    expiresAt: Date.now() + REFRESH_TOKEN_TTL_SECONDS * 1000,
  };

  return {
    accessToken: await signPayload(accessPayload),
    refreshToken: await signPayload(refreshPayload),
    sessionId,
  };
}

/** Error response shape per RFC 6749 §5.2: {error, error_description}. */
export function oauthError(status: number, error: string, description: string): Response {
  return Response.json(
    { error, error_description: description },
    { status, headers: { "cache-control": "no-store" } },
  );
}
