"use client";

/**
 * Client-side wrapper around the dynamically-imported PixelTrail.
 *
 * `next/dynamic` with `ssr: false` is not allowed inside Server
 * Components in Next.js 15 App Router — it must live in a client
 * component. This thin wrapper lets `app/page.tsx` (a Server
 * Component) import a server-safe alias while the heavy three.js
 * chunk loads only on the client, with the Mosaic-palette
 * AILoadingState as the fallback.
 */

import dynamic from "next/dynamic";

import AILoadingState from "./AILoadingState";
import type { PixelTrailProps } from "./PixelTrail";

const PixelTrail = dynamic(() => import("./PixelTrail"), {
  ssr: false,
  loading: () => <AILoadingState />,
});

export default function LazyPixelTrail(props: PixelTrailProps) {
  return <PixelTrail {...props} />;
}
