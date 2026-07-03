"use client";

/**
 * Flow steps 5–8: the redirect_uri page.
 *
 * The provider sent the browser back here with `?code=...&state=...`.
 * This page:
 *
 *   5. Validates `state` against the value stored before the redirect
 *      (CSRF check — reject callbacks we never initiated).
 *   6. Exchanges code + code_verifier for an access token: a direct
 *      fetch() POST to the token endpoint. This is the PKCE moment.
 *   7. Receives the access token.
 *   8. Uses it to fetch the user's profile from a protected endpoint.
 *
 * Every intermediate value is kept in component state and rendered, so you
 * can SEE the protocol run. A real app would show none of this — it would
 * store the session and redirect home.
 */

import { useEffect, useRef, useState } from "react";
import { oauthConfig, storageKeys } from "@/lib/oauth-config";

type TraceStep = {
  title: string;
  detail: string;
  data?: string;
  failed?: boolean;
};

export default function CallbackPage() {
  const [steps, setSteps] = useState<TraceStep[]>([]);
  const [done, setDone] = useState(false);
  // React 18+ dev "Strict Mode" runs effects twice to surface bugs. Without
  // this guard the second run would replay the code exchange — and fail,
  // because authorization codes are single-use. (A nice accidental demo of
  // exactly that rule.)
  const started = useRef(false);

  useEffect(() => {
    if (started.current) return;
    started.current = true;

    const addStep = (step: TraceStep) => setSteps((previous) => [...previous, step]);

    async function completeLogin() {
      const params = new URLSearchParams(window.location.search);

      // The provider reports failures (e.g. the user clicked Deny) as
      // ?error=... on this same redirect.
      const error = params.get("error");
      if (error) {
        addStep({
          title: "Provider returned an error",
          detail: `${error}: ${params.get("error_description") ?? "(no description)"}`,
          failed: true,
        });
        return;
      }

      const code = params.get("code");
      const returnedState = params.get("state");

      // Pull the values stashed before the redirect — and remove them:
      // they are strictly one-shot.
      const expectedState = sessionStorage.getItem(storageKeys.state);
      const codeVerifier = sessionStorage.getItem(storageKeys.codeVerifier);
      sessionStorage.removeItem(storageKeys.state);
      sessionStorage.removeItem(storageKeys.codeVerifier);

      // ── Step 5: CSRF check ────────────────────────────────────────────
      if (!code || !expectedState || !codeVerifier || returnedState !== expectedState) {
        addStep({
          title: "Step 5 — state check FAILED",
          detail:
            "The returned state does not match the stored one (or this page was " +
            "opened without going through the sign-in flow). Aborting: this " +
            "callback was not initiated by us.",
          failed: true,
        });
        return;
      }
      addStep({
        title: "Step 5 — state matches ✓",
        detail: "The callback belongs to a login this tab started.",
        data: `state (returned == stored): ${returnedState}`,
      });
      addStep({
        title: "Received one-time authorization code",
        detail: "Useless on its own without our code_verifier — that is PKCE.",
        data: code,
      });

      // ── Step 6: exchange code + verifier for a token ──────────────────
      // Plain fetch, form-encoded body, exactly as RFC 6749 §4.1.3 asks.
      // Note there is no client_secret — the code_verifier plays that role,
      // but scoped to this single login.
      const tokenResponse = await fetch(oauthConfig.tokenEndpoint, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code,
          redirect_uri: `${window.location.origin}${oauthConfig.redirectPath}`,
          client_id: oauthConfig.clientId,
          code_verifier: codeVerifier, // revealed only here, over this direct HTTPS call
        }),
      });
      const tokenBody = await tokenResponse.json();

      if (!tokenResponse.ok) {
        addStep({
          title: "Step 6 — token exchange FAILED",
          detail: "The provider rejected the exchange.",
          data: JSON.stringify(tokenBody, null, 2),
          failed: true,
        });
        return;
      }
      addStep({
        title: "Step 6 — code_verifier sent, PKCE check passed ✓",
        detail: "SHA-256(code_verifier) matched the code_challenge from the start of the flow.",
        data: `code_verifier: ${codeVerifier}`,
      });

      // ── Step 7: we have an access token ───────────────────────────────
      // Kept in a local variable on purpose. Persisting tokens in
      // localStorage makes them readable by any XSS payload; real apps use
      // in-memory storage + refresh tokens in httpOnly cookies, or keep
      // tokens server-side entirely.
      const accessToken: string = tokenBody.access_token;
      addStep({
        title: "Step 7 — access token received",
        detail: "Bearer token: whoever holds it can call the API, so it is never put in a URL.",
        data: JSON.stringify(tokenBody, null, 2),
      });

      // ── Step 8: call a protected API with it ──────────────────────────
      const userInfoResponse = await fetch(oauthConfig.userInfoEndpoint, {
        headers: { authorization: `Bearer ${accessToken}` },
      });
      const profile = await userInfoResponse.json();

      if (!userInfoResponse.ok) {
        addStep({
          title: "Step 8 — userinfo request FAILED",
          detail: "The API rejected the token.",
          data: JSON.stringify(profile, null, 2),
          failed: true,
        });
        return;
      }
      addStep({
        title: "Step 8 — logged in 🎉",
        detail: "Profile fetched from the protected endpoint with the Bearer token.",
        data: JSON.stringify(profile, null, 2),
      });
      setDone(true);
    }

    completeLogin().catch((unexpected: unknown) => {
      addStep({
        title: "Unexpected error",
        detail: String(unexpected),
        failed: true,
      });
    });
  }, []);

  return (
    <>
      <h1>Callback — completing the login</h1>
      <p>
        This page is the registered <code>redirect_uri</code>. Below is the
        live trace of steps 5–8 of the flow.
      </p>
      {steps.map((step) => (
        <div key={step.title} className={`step ${step.failed ? "error" : ""} ${done && !step.failed ? "success" : ""}`}>
          <span className="label">{step.failed ? "FAILED" : "OK"}</span>
          <h3>{step.title}</h3>
          <p>{step.detail}</p>
          {step.data && <pre>{step.data}</pre>}
        </div>
      ))}
      <p>
        <a href="/">← Start over</a>
      </p>
    </>
  );
}
