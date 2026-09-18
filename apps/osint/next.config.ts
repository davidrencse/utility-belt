import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Allow the dev server to serve _next assets/HMR when accessed over the LAN IP
  // (not just localhost). Without this, hitting the app at http://10.20.56.49:3000
  // gets its client JS blocked → page renders but is non-interactive.
  allowedDevOrigins: ["10.20.56.49"],

  // Keep these out of the Server/Route bundle and require them natively at
  // runtime. exifr does optional `fs`/`zlib` requires the bundler can't resolve
  // (the "Couldn't load fs / Couldn't load zlib" warnings) — externalizing it
  // makes those builtins resolve normally. sharp is a native (.node) addon.
  // (sharp is already in Next's default external list; listed here for clarity.)
  serverExternalPackages: ["sharp", "exifr"],
};

export default nextConfig;
