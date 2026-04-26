# Deploy

The site lives under `mosaic/site/` inside the Rust workspace
repository. Vercel needs to know that the Next.js project is in a
subdirectory — by default it inspects the repo root and sees only
`Cargo.toml`, which is why a stock import returns a 404.

There are two ways to make this work; pick **one**.

## Option A — `vercel.json` at the repo root (recommended)

This is the configuration committed at `mosaic/vercel.json`. It tells
Vercel to:

- treat the project as a Next.js app (`"framework": "nextjs"`),
- run `pnpm install --frozen-lockfile` and `pnpm build` inside `site/`,
- read the build output from `site/.next`.

With `vercel.json` in place, your Vercel project's **Settings →
General → Root Directory** must be **left empty** (or set to `.`).
If you previously set Root Directory to `site` to make the deployment
work, change it back to empty so Vercel reads `vercel.json` from the
repo root.

Then trigger a fresh deployment:

```bash
# Vercel CLI
vercel --prod

# or push any commit to main and let the GitHub integration redeploy
git commit --allow-empty -m "chore: trigger vercel rebuild"
git push origin main
```

## Option B — Vercel Dashboard "Root Directory = site"

If you prefer not to keep `vercel.json` in the repo, you can instead:

1. Open the Vercel project's **Settings → General**.
2. Set **Root Directory** to `site`.
3. Leave Framework as auto-detect; Vercel will see `site/package.json`
   and pick Next.js.
4. Leave Install Command, Build Command, and Output Directory empty
   (auto-detected).
5. Redeploy.

In this mode the repo-root `vercel.json` is ignored. Both options work;
Option A keeps the configuration in source control.

## .vercelignore

`mosaic/.vercelignore` excludes the Rust workspace, target/, docs,
ADR, supply-chain, and unrelated markdown from the deployment upload.
This keeps the Vercel build environment small and makes the install +
build steps faster.

## Custom domain

The intended public domain is `mosaic.wienerlabs.xyz`. Add a CNAME
record on `wienerlabs.xyz` pointing to `cname.vercel-dns.com` and
register the same domain in **Settings → Domains** on the Vercel
project. The site's metadata (`metadataBase`, `openGraph.url`,
`alternates.canonical`) is already pinned to that hostname.

## Why a 404?

The 404 you saw is Vercel's "no Next.js detected" page, not a
Next.js 404. With `vercel.json` (Option A) or Root Directory = `site`
(Option B), Vercel finds `site/app/page.tsx` and serves the splash
correctly.
