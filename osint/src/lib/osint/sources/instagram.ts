import type { Source, Finding } from "../types";

// Instagram as a GEOLOCATION pivot — NOT person/profile OSINT.
//
// Once the pipeline names a place or landmark (from EXIF/IPTC tags, the AI visual
// estimate, or geocoding), Instagram is a strong corroboration tool: its
// location pages and hashtags aggregate geotagged photos of that exact spot.
// Comparing those against the subject image confirms or refines the location and
// can reveal the precise vantage point. No API key needed — these are public
// search/explore links the analyst opens manually (IG's private API + paid
// scrapers are out of the free scope).
//
// Acts ONLY on human-readable place names. Bare coordinates and already-geocoded
// coordinate entities are skipped (nothing to search by name), so this fires on
// the city/region/landmark text that geovision and exif surface.

const COORD_RE = /^\s*-?\d+(?:\.\d+)?\s*,\s*-?\d+(?:\.\d+)?/;
const q = (s: string) => encodeURIComponent(s);

/** collapse a place phrase to an Instagram-style hashtag token */
function hashtag(place: string): string {
  return place
    .split(",")[0] // first segment: the most specific name
    .toLowerCase()
    .normalize("NFD")
    .replace(/[̀-ͯ]/g, "") // strip accents
    .replace(/[^a-z0-9]/g, "");
}

const instagramSource: Source = {
  id: "instagram",
  label: "Instagram Geo-Pivot",
  handles: ["location"],
  async run(e) {
    const m = e.meta as { lat?: number; lon?: number; geocoded?: boolean } | undefined;
    // skip coordinate-only / already-resolved points — nothing to search by name
    if ((m?.lat != null && m?.lon != null) || m?.geocoded || COORD_RE.test(e.value)) return [];

    const place = e.value.trim();
    if (place.length < 3) return [];
    const tag = hashtag(place);
    if (!tag) return [];

    return [
      {
        source: "instagram",
        title: `Instagram geo-pivot: ${place}`,
        severity: "info",
        detail:
          "Compare geotagged Instagram posts of this place against the photo to confirm/refine the location and pin the vantage point.",
        data: {
          place,
          links: [
            { label: `#${tag} (geotagged photos)`, url: `https://www.instagram.com/explore/tags/${q(tag)}/` },
            { label: "IG location pages", url: `https://www.google.com/search?q=${q(`site:instagram.com/explore/locations "${place}"`)}` },
            { label: "Posts mentioning place", url: `https://www.google.com/search?q=${q(`site:instagram.com "${place}"`)}` },
          ],
          note: "Geolocation corroboration only — match scenery/landmarks, do not identify individuals.",
        },
      } as Finding,
    ];
  },
};

export default instagramSource;
