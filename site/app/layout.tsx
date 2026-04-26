import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  metadataBase: new URL("https://mosaic.wienerlabs.xyz"),
  title: {
    default: "Mosaic — multi-proof verifier library for Solana",
    template: "%s · Mosaic by Wiener Labs",
  },
  description:
    "A Wiener Labs product. Proof-system-agnostic on-chain verification for Solana. One trait, six proving systems: Groth16, KZG-PLONK, HyperPlonk, Halo2-KZG, Nova family, FRI-STARK.",
  applicationName: "Mosaic",
  keywords: [
    "Mosaic",
    "Wiener Labs",
    "Solana",
    "zero-knowledge",
    "zk verifier",
    "Groth16",
    "PLONK",
    "HyperPlonk",
    "Halo2",
    "Nova",
    "STARK",
    "alt_bn128",
    "BN254",
    "SBF",
    "applied cryptography",
  ],
  authors: [{ name: "Wiener Labs", url: "https://www.wienerlabs.xyz/" }],
  creator: "Wiener Labs",
  publisher: "Wiener Labs",
  category: "technology",
  openGraph: {
    type: "website",
    siteName: "Mosaic · A Wiener Labs Product",
    title: "Mosaic — multi-proof verifier library for Solana",
    description:
      "Proof-system-agnostic on-chain verification for Solana. Built and maintained by Wiener Labs, an applied cryptography studio.",
    url: "https://mosaic.wienerlabs.xyz",
    locale: "en_US",
  },
  twitter: {
    card: "summary_large_image",
    site: "@mosaiczk",
    creator: "@mosaiczk",
    title: "Mosaic — multi-proof verifier library for Solana",
    description:
      "A Wiener Labs product. Six proving systems behind one verifier trait. Open source, audit-first, Solana-native.",
  },
  robots: {
    index: true,
    follow: true,
  },
  alternates: {
    canonical: "https://mosaic.wienerlabs.xyz",
  },
};

const themeBootstrap = `
  (function () {
    try {
      var stored = localStorage.getItem("mosaic-theme");
      var theme = stored === "dark" || stored === "light" ? stored : "light";
      document.documentElement.setAttribute("data-theme", theme);
    } catch (e) {}
  })();
`;

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" data-theme="light" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeBootstrap }} />
      </head>
      <body>{children}</body>
    </html>
  );
}
