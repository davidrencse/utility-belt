import type { Metadata } from "next";
import { Instrument_Serif, JetBrains_Mono } from "next/font/google";
import "./globals.css";

// Display: Instrument Serif — high-contrast editorial serif. The single
// un-technical voice (wordmark, headline numbers) against the mono data, giving
// the tool an intelligence-dossier refinement instead of cyberpunk-HUD noise.
// Data/body: JetBrains Mono — forensic, tabular, legible at small + large sizes.
const display = Instrument_Serif({
  variable: "--font-display",
  subsets: ["latin"],
  weight: "400",
  style: ["normal", "italic"],
});

const mono = JetBrains_Mono({
  variable: "--font-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "Geolocator — where was this photo taken?",
  description:
    "Find where a photo was taken: EXIF GPS, AI estimation from pixel content, reverse image search, and geocoded place names — every signal fused onto one map.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      className={`${display.variable} ${mono.variable} h-full antialiased`}
    >
      <head>
        {/* Open the TLS+DNS connections to the map tile/glyph/elevation origins up
            front so the FIRST map tiles start downloading the instant MapView
            mounts, instead of paying a cold handshake then. Tiles + glyph PBFs are
            CORS-fetched, so preconnect must be crossOrigin. openfreemap (vector +
            fonts) and AWS S3 (elevation/terrarium DEM) back the default recon map;
            arcgis only loads in Satellite mode → dns-prefetch is enough there. */}
        <link rel="preconnect" href="https://tiles.openfreemap.org" crossOrigin="anonymous" />
        <link rel="preconnect" href="https://s3.amazonaws.com" crossOrigin="anonymous" />
        <link rel="dns-prefetch" href="https://server.arcgisonline.com" />
      </head>
      <body className="min-h-full flex flex-col">{children}</body>
    </html>
  );
}
