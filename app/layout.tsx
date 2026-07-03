import type { Metadata } from "next";
import type { ReactNode } from "react";
import "./globals.css";

export const metadata: Metadata = {
  title: "OAuth 2.0 + PKCE from scratch",
  description:
    "Educational implementation of the OAuth 2.0 Authorization Code flow with PKCE in Next.js — no auth libraries, just fetch and Web Crypto.",
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
