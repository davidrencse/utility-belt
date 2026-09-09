# Image Geolocator

Upload a photo — it estimates **where it was taken** and plots it on a map.
Three independent signals, fused into ranked map points:

1. **EXIF GPS** — exact device fix embedded in the file (when present).
2. **IPTC/XMP place tags** — embedded city/region/country text.
3. **AI visual estimate** — a vision model reads pixel content (signs, language,
   architecture, vegetation, traffic side, license-plate formats…) and commits to
   the most likely location, GeoGuessr-style — works even with zero metadata.

Named landmarks/places (from tags or the AI) are **geocoded** via OpenStreetMap
into coordinates. Independent sources that agree on the same spot are fused into a
single corroborated point with boosted confidence.

> ⚠️ AI visual estimates are inferences, not facts — verify before relying on them.
> The app does not identify private individuals.

## Run

```bash
npm install
cp .env.example .env.local   # optional — see below
npm run dev                  # http://localhost:3000
```

Drop, paste, or choose one or more images, then hit **locate**.

## Keys

Everything except the AI estimate is **free and keyless** (EXIF, place tags,
OpenStreetMap geocoding). For the AI visual estimate set one key in `.env.local`:

```
VISION_API_KEY=gsk_...        # Groq, free tier — default provider
```

Any OpenAI-compatible vision API works; override `VISION_BASE_URL` / `VISION_MODEL`
to switch providers (e.g. Google Gemini free tier). See `.env.example`.

## How it works

`src/lib/osint/engine.ts` runs each uploaded image through the sources in
`src/lib/osint/sources/` (`exif`, `geovision`, `geocode`), feeds discovered place
names back through geocoding, then `src/lib/osint/geo.ts` fuses the resulting
location points — clustering by accuracy radius and combining confidence via
noisy-OR — into the ranked points shown on the map (`src/components/MapView.tsx`).

| Source | Input | Key | What |
|---|---|---|---|
| `exif` | image | — | EXIF GPS + IPTC/XMP place tags |
| `geovision` | image | `VISION_API_KEY` | AI location estimate from pixel content |
| `geocode` | place name | — | OpenStreetMap (Nominatim) → coordinates |

## Stack

Next.js (App Router) · React 19 · MapLibre GL (OpenFreeMap basemap) · `exifr` ·
Tailwind v4.
