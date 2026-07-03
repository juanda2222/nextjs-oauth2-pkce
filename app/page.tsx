import { SignInButton } from "./sign-in-button";

/**
 * Home page. Static explanation + the button that kicks off the flow.
 * The interesting client-side code lives in ./sign-in-button.tsx (steps 1–2)
 * and ./callback/page.tsx (steps 5–8).
 */
export default function HomePage() {
  return (
    <>
      <h1>OAuth 2.0 Authorization Code flow + PKCE, from scratch</h1>
      <p>
        This app signs you in using the <strong>Authorization Code flow with
        PKCE</strong> — the flow you should use for any browser or mobile app —
        implemented with nothing but <code>fetch</code> and the Web Crypto API.
        No auth libraries. It talks to a mock OAuth provider that lives in this
        same repo under <code>app/oauth/</code>, so you can read both sides of
        the protocol.
      </p>

      <SignInButton />

      <h2>What will happen when you click</h2>
      <ol>
        <li>
          The browser generates a random secret (the <code>code_verifier</code>)
          and stores it in <code>sessionStorage</code>. It never leaves this tab
          until the very last step.
        </li>
        <li>
          It computes <code>code_challenge = SHA-256(code_verifier)</code> and
          redirects you to the provider&apos;s consent screen with that hash.
        </li>
        <li>
          You approve, and the provider redirects back to{" "}
          <code>/callback</code> with a one-time <code>code</code>.
        </li>
        <li>
          The callback page exchanges <code>code + code_verifier</code> for an
          access token via a direct <code>fetch</code> — and the provider only
          accepts it because the hash of the verifier matches the challenge
          from step 2.
        </li>
        <li>
          The access token is used to <code>fetch</code> the user&apos;s
          profile. Every intermediate value is shown on screen.
        </li>
      </ol>

      <p>
        Start reading at <code>lib/pkce.ts</code>, then follow the numbered
        steps in the file comments. The README has the full sequence diagram.
      </p>
    </>
  );
}
