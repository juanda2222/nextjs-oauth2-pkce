"use client";

/**
 * The APP / SDK — the public client that drives the whole flow.
 *
 * "use client": this is the code that would live inside a partner's mobile
 * or web app. It is the ONLY holder of the PKCE code_verifier.
 *
 * Unlike the redirect-based flow, nothing here navigates away: every hop is
 * a fetch(), so the entire sign-in happens within one page lifetime and the
 * verifier can live in a local variable — no sessionStorage, nothing
 * persisted, nothing logged.
 *
 * The demo runs the full session arc and renders every intermediate value:
 *
 *   1. generate PKCE pair            (in the app)
 *   2. ask the partner backend to vouch → one-time code   (challenge only!)
 *   5. exchange code + verifier for member tokens         (direct fetch)
 *   6. call a protected member endpoint
 *   7. refresh: rotate the pair, prove the old one is dead
 *   8. logout: revoke, prove the access token is dead
 *
 * (Steps 3–4 happen server-side between partner backend and TES — watch
 * them in app/partner/session/route.ts and app/tes/authorize/route.ts.)
 * A real SDK does all of this silently; the trace exists to teach.
 */

import { useState } from "react";
import { base64UrlToString } from "@/lib/base64url.shared";
import { createCodeChallenge, createCodeVerifier } from "@/lib/pkce.client";
import { demoMembers, sdkConfig } from "@/lib/sdk-config.client";

type TraceStep = {
  title: string;
  detail: string;
  data?: string;
  failed?: boolean;
};

/** Decode a demo token's payload half for display (it is just base64url JSON). */
function decodeClaims(token: string): string {
  return JSON.stringify(JSON.parse(base64UrlToString(token.split(".")[0])), null, 2);
}

export function SdkDemo() {
  const [steps, setSteps] = useState<TraceStep[]>([]);
  const [running, setRunning] = useState(false);

  async function runFlow(memberId: string) {
    setRunning(true);
    setSteps([]);
    const addStep = (step: TraceStep) => setSteps((previous) => [...previous, step]);

    try {
      // ── Step 1: PKCE pair — the verifier never leaves this function ────
      const codeVerifier = createCodeVerifier();
      const codeChallenge = await createCodeChallenge(codeVerifier);
      addStep({
        title: "Step 1 — PKCE pair generated in the app",
        detail:
          "The verifier lives in a local variable: not sessionStorage, not a cookie, " +
          "never sent to the partner backend, never logged.",
        data: `code_verifier (stays here): ${codeVerifier}\ncode_challenge = S256(verifier): ${codeChallenge}`,
      });

      // ── Step 2: hand the CHALLENGE to the partner backend, get a code ──
      // The member is "already signed in" to the partner app; the backend
      // vouches for them at the TES (steps 3–4, server-side) and relays the
      // one-time code back. No redirect: the code arrives in a JSON body.
      const sessionResponse = await fetch(sdkConfig.partnerSessionEndpoint, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ memberId, codeChallenge }),
      });
      const sessionBody = await sessionResponse.json();

      if (!sessionResponse.ok) {
        addStep({
          title: `Step 2 — vouch FAILED for ${memberId}`,
          detail:
            sessionBody.error === "member_not_provisioned"
              ? "The TES refused: this member was never provisioned. Provision-before-sign-in " +
                "is the rule — the partner backend would provision the member and retry, and " +
                "the next attempt would succeed."
              : "The partner backend / TES rejected the vouch.",
          data: JSON.stringify(sessionBody, null, 2),
          failed: true,
        });
        return;
      }
      const code: string = sessionBody.code;
      addStep({
        title: "Steps 2–4 — partner vouched, one-time code received",
        detail:
          "The app sent only the challenge (a hash). The backend called the TES with its " +
          "confidential server-key and relayed back this code — which the backend itself " +
          "cannot redeem, because redeeming requires the verifier.",
        data: `code (single-use, ~60s, challenge sealed inside): ${code}`,
      });

      // ── Step 5: exchange code + verifier for the member token pair ─────
      const tokenResponse = await fetch(sdkConfig.tokenEndpoint, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code,
          code_verifier: codeVerifier, // revealed only here, over this direct call
          client_id: sdkConfig.clientKey,
        }),
      });
      const tokenBody = await tokenResponse.json();
      if (!tokenResponse.ok) {
        addStep({
          title: "Step 5 — token exchange FAILED",
          detail: "The TES rejected the exchange.",
          data: JSON.stringify(tokenBody, null, 2),
          failed: true,
        });
        return;
      }
      // Tokens held in local variables on purpose: localStorage is readable
      // by any XSS payload. Real SDKs use platform-secure storage
      // (Keychain/Keystore) via an abstraction that never logs values.
      let accessToken: string = tokenBody.access_token;
      let refreshToken: string = tokenBody.refresh_token;
      addStep({
        title: "Step 5 — PKCE passed, member token pair minted",
        detail:
          "S256(code_verifier) matched the challenge inside the code. The claims are " +
          "self-describing — issuer, member (sub), audience, organization, scope, and a " +
          "session id (jti) that makes rotation and revocation possible:",
        data: `access_token claims:\n${decodeClaims(accessToken)}`,
      });

      // ── Step 6: call a protected member endpoint ────────────────────────
      const profileResponse = await fetch(sdkConfig.memberProfileEndpoint, {
        headers: { authorization: `Bearer ${accessToken}` },
      });
      const profile = await profileResponse.json();
      addStep({
        title: "Step 6 — member endpoint called with the Bearer token",
        detail: "The endpoint verified the token locally (signature, expiry, iss, aud) — it never called the TES.",
        data: JSON.stringify(profile, null, 2),
        failed: !profileResponse.ok,
      });
      if (!profileResponse.ok) return;

      // ── Step 7: refresh (rotation) ──────────────────────────────────────
      const oldRefreshToken = refreshToken;
      const refreshResponse = await fetch(sdkConfig.refreshEndpoint, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: refreshToken }),
      });
      const refreshBody = await refreshResponse.json();
      if (!refreshResponse.ok) {
        addStep({ title: "Step 7 — refresh FAILED", detail: "", data: JSON.stringify(refreshBody, null, 2), failed: true });
        return;
      }
      accessToken = refreshBody.access_token;
      refreshToken = refreshBody.refresh_token;

      // Prove rotation: replaying the OLD refresh token must now fail.
      const replayResponse = await fetch(sdkConfig.refreshEndpoint, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: oldRefreshToken }),
      });
      addStep({
        title: "Step 7 — refreshed: pair rotated, old pair dead",
        detail:
          `Identity was re-resolved and a new session id was minted. Replaying the OLD ` +
          `refresh token now fails with HTTP ${replayResponse.status} — in production that ` +
          "replay is a theft signal worth alerting on.",
        data: `new access_token claims (note the new jti):\n${decodeClaims(accessToken)}`,
      });

      // ── Step 8: logout = server-side revocation ─────────────────────────
      await fetch(sdkConfig.revokeEndpoint, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ token: refreshToken }),
      });
      const afterRevoke = await fetch(sdkConfig.memberProfileEndpoint, {
        headers: { authorization: `Bearer ${accessToken}` },
      });
      addStep({
        title: "Step 8 — logged out: session revoked server-side",
        detail:
          `The same access token that worked in step 6 now gets HTTP ${afterRevoke.status} ` +
          "from the member endpoint. This is why the platform owns the issuer: a stateless " +
          "third-party token would have kept working until expiry.",
        data: JSON.stringify(await afterRevoke.json(), null, 2),
        failed: afterRevoke.status !== 401,
      });
    } catch (unexpected) {
      addStep({ title: "Unexpected error", detail: String(unexpected), failed: true });
    } finally {
      setRunning(false);
    }
  }

  return (
    <>
      <p>
        <button className="primary" disabled={running} onClick={() => void runFlow(demoMembers.provisioned)}>
          Sign in as {demoMembers.provisioned}
        </button>{" "}
        <button className="secondary" disabled={running} onClick={() => void runFlow(demoMembers.notProvisioned)}>
          Sign in as {demoMembers.notProvisioned} (never provisioned)
        </button>
      </p>
      {steps.map((step) => (
        <div key={step.title} className={`step ${step.failed ? "error" : "success"}`}>
          <span className="label">{step.failed ? "STOPPED" : "OK"}</span>
          <h3>{step.title}</h3>
          <p>{step.detail}</p>
          {step.data && <pre>{step.data}</pre>}
        </div>
      ))}
    </>
  );
}
