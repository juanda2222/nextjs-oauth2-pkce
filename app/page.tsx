import { SdkDemo } from "./sdk-demo.client";

/**
 * Home page. Static explanation + the demo runner.
 * The interesting client-side code lives in ./sdk-demo.client.tsx; the
 * server actors live in app/partner/ (partner backend), app/tes/ (Token
 * Exchange Service) and app/pager/ (the platform's member APIs).
 */
export default function HomePage() {
  return (
    <>
      <h1>Backend-vouched authorization code + PKCE, from scratch</h1>
      <p>
        This app signs a member in using an <strong>OAuth 2.0-style
        authorization-code grant hardened with PKCE</strong> — but with a
        twist on the textbook flow: there is <strong>no browser redirect, no
        login form, no consent screen</strong>. The member is already signed
        in to the <em>partner&apos;s</em> app; the partner&apos;s backend{" "}
        <strong>vouches</strong> for them with a confidential server-key, and
        a <strong>Token Exchange Service</strong> mints the one-time code and
        the member tokens. Everything is implemented with{" "}
        <code>fetch</code> and the Web Crypto API — no auth libraries.
      </p>
      <p>
        Every actor lives in this repo, each under its own route directory,
        so you can read every side:
      </p>
      <ul>
        <li>
          <strong>the app / SDK</strong> (public client, holds the PKCE
          verifier) — <code>app/sdk-demo.client.tsx</code>
        </li>
        <li>
          <strong>the partner backend</strong> (holds the confidential
          server-key, vouches for its members) — <code>app/partner/*</code>
        </li>
        <li>
          <strong>the Token Exchange Service</strong> (mints codes and
          tokens, owns revocation) — <code>app/tes/*</code>
        </li>
        <li>
          <strong>the platform&apos;s member APIs</strong> (protected
          endpoints that verify the token locally) — <code>app/pager/*</code>
        </li>
      </ul>

      <h2>Run it</h2>
      <p>
        The first button runs the full session arc — vouch, code, PKCE
        exchange, API call, refresh rotation, revoke — showing every
        intermediate value. The second signs in a member the partner never
        provisioned, to show the <code>member_not_provisioned</code> path.
      </p>

      <SdkDemo />

      <p>
        Start reading at <code>lib/pkce.client.ts</code>, then follow the
        numbered steps in the file comments. The README has the sequence
        diagram and a comparison with the classic redirect-based flow.
      </p>
    </>
  );
}
