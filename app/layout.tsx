import type { Metadata } from "next";
import type { ReactNode } from "react";
import "./globals.css";

export const metadata: Metadata = {
  title: "Backend-vouched auth code + PKCE from scratch",
  description:
    "Educational OAuth 2.0-style token exchange in Next.js: a partner backend vouches for a member, a Token Exchange Service mints PKCE-bound codes and tokens. No auth libraries, just fetch and Web Crypto.",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>
        <main>{children}</main>
      </body>
    </html>
  );
}
