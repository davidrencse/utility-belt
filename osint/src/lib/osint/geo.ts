import type { Entity, GeoPoint, GeoKind } from "./types";
import { safeFetch } from "./util";

// Geo fusion: turn location entities (from EXIF GPS, AI visual estimates,
// geocoded place names, IP geolocation) into a ranked, de-duplicated set of map
// points. Independent sources that agree on the same spot are FUSED into one
// point with boosted confidence (corroboration) instead of being plotted as
// separate scattered dots.

const COORD_RE = /^\s*(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)\s*$/;

// default accuracy radius (km) per precision class when a source gives none
const DEFAULT_RADIUS: Record<GeoKind, number> = {
  gps: 0.05, // exact device fix
  geocoded: 5, // place/landmark center
  estimate: 25, // AI city-level guess
};

function kindForSource(source: string): GeoKind {
  if (source === "exif") return "gps";
  if (source === "geovision" || source === "scene") return "estimate";
  return "geocoded";
}

/** great-circle distance in km */
export function haversineKm(aLat: number, aLon: number, bLat: number, bLon: number): number {
  const R = 6371;
  const dLat = ((bLat - aLat) * Math.PI) / 180;
  const dLon = ((bLon - aLon) * Math.PI) / 180;
  const la1 = (aLat * Math.PI) / 180;
  const la2 = (bLat * Math.PI) / 180;
  const h =
    Math.sin(dLat / 2) ** 2 + Math.cos(la1) * Math.cos(la2) * Math.sin(dLon / 2) ** 2;
  return 2 * R * Math.asin(Math.min(1, Math.sqrt(h)));
}

const R_EARTH = 6371;

/**
 * Forward geodesic: starting at (lat,lon), travel `distanceKm` along a compass
 * `bearingDeg` (0=N, 90=E) and return the destination [lat, lon].
 *
 * Used to recover a PHOTOGRAPHER'S position from the SUBJECT they shot: a photo
 * of a landmark is not taken *at* the landmark but some distance away, looking
 * toward it. Given the subject's coords, the camera→subject look bearing θ and
 * the distance d, the camera sits at bearing (θ+180) from the subject, d away.
 */
export function destinationPoint(
  lat: number,
  lon: number,
  bearingDeg: number,
  distanceKm: number,
): [number, number] {
  const d = distanceKm / R_EARTH; // angular distance
  const θ = (bearingDeg * Math.PI) / 180;
  const φ1 = (lat * Math.PI) / 180;
  const λ1 = (lon * Math.PI) / 180;
  const sinφ2 = Math.sin(φ1) * Math.cos(d) + Math.cos(φ1) * Math.sin(d) * Math.cos(θ);
  const φ2 = Math.asin(Math.min(1, Math.max(-1, sinφ2)));
  const λ2 =
    λ1 +
    Math.atan2(
      Math.sin(θ) * Math.sin(d) * Math.cos(φ1),
      Math.cos(d) - Math.sin(φ1) * sinφ2,
    );
  return [(φ2 * 180) / Math.PI, (((λ2 * 180) / Math.PI + 540) % 360) - 180];
}

/** compass bearing (deg) → 8-point label */
export function compass8(deg: number): string {
  const dirs = ["N", "NE", "E", "SE", "S", "SW", "W", "NW"];
  return dirs[Math.round((((deg % 360) + 360) % 360) / 45) % 8];
}

/**
 * Attach ground elevation (metres above sea level) to each fused point via the
 * free, no-key Open-Meteo DEM. One batched request for all points. Best-effort:
 * any failure leaves elevation undefined rather than breaking the run.
 */
export async function attachElevation(points: GeoPoint[], signal?: AbortSignal): Promise<void> {
  if (!points.length) return;
  const lat = points.map((p) => p.lat.toFixed(5)).join(",");
  const lon = points.map((p) => p.lon.toFixed(5)).join(",");
  try {
    const res = await safeFetch(
      `https://api.open-meteo.com/v1/elevation?latitude=${lat}&longitude=${lon}`,
      { headers: { accept: "application/json" } },
      // Best-effort enrichment that runs serially at the very end and blocks the
      // response — keep its worst-case tail short rather than the default long wait.
      4500,
      signal,
    );
    if (!res.ok) return;
    const j = (await res.json()) as { elevation?: number[] };
    if (!Array.isArray(j.elevation)) return;
    points.forEach((p, i) => {
      if (typeof j.elevation![i] === "number") p.elevationM = Math.round(j.elevation![i]);
    });
  } catch {
    // elevation is a nice-to-have enrichment; never let it fail the geolocation
  }
}

interface RawPoint {
  lat: number;
  lon: number;
  label: string;
  source: string;
  confidence: number;
  kind: GeoKind;
  radiusKm: number;
}

function rawFromEntity(e: Entity): RawPoint | null {
  if (e.type !== "location") return null;
  const m = e.meta as
    | { lat?: number; lon?: number; radiusKm?: number; kind?: GeoKind }
    | undefined;
  let lat = m?.lat;
  let lon = m?.lon;
  if (lat == null || lon == null) {
    const mt = COORD_RE.exec(e.value);
    if (mt) {
      lat = parseFloat(mt[1]);
      lon = parseFloat(mt[2]);
    }
  }
  if (typeof lat !== "number" || typeof lon !== "number" || Number.isNaN(lat) || Number.isNaN(lon))
    return null;
  if (Math.abs(lat) > 90 || Math.abs(lon) > 180) return null;
  const kind = m?.kind || kindForSource(e.source);
  const radiusKm = typeof m?.radiusKm === "number" ? m.radiusKm : DEFAULT_RADIUS[kind];
  return { lat, lon, label: e.value, source: e.source, confidence: e.confidence, kind, radiusKm };
}

// precision rank — smaller is more precise (used to pick a cluster's representative)
const KIND_RANK: Record<GeoKind, number> = { gps: 0, geocoded: 1, estimate: 2 };

interface Cluster {
  rep: RawPoint; // most precise member, used for center/label/kind
  members: RawPoint[];
  sources: Set<string>;
}

/**
 * Build fused, ranked map points from the entity graph.
 * - groups points that fall within each other's accuracy radius
 * - the most precise member defines the cluster center/label/kind
 * - confidence is combined via noisy-OR so independent agreement raises it
 */
export function buildGeo(entities: Entity[]): GeoPoint[] {
  const raws = entities.map(rawFromEntity).filter((p): p is RawPoint => p !== null);
  // most precise + most confident first so they seed clusters
  raws.sort((a, b) => KIND_RANK[a.kind] - KIND_RANK[b.kind] || b.confidence - a.confidence);

  const clusters: Cluster[] = [];
  for (const p of raws) {
    let placed = false;
    for (const c of clusters) {
      const d = haversineKm(c.rep.lat, c.rep.lon, p.lat, p.lon);
      // agree if within the coarser of the two accuracy radii (+ small slack)
      if (d <= Math.max(c.rep.radiusKm, p.radiusKm) + 0.5) {
        c.members.push(p);
        c.sources.add(p.source);
        if (KIND_RANK[p.kind] < KIND_RANK[c.rep.kind]) c.rep = p; // tighter fix wins
        placed = true;
        break;
      }
    }
    if (!placed) clusters.push({ rep: p, members: [p], sources: new Set([p.source]) });
  }

  return clusters
    .map((c) => {
      // noisy-OR over distinct sources: independent agreement => higher confidence
      const bySource = new Map<string, number>();
      for (const m of c.members) bySource.set(m.source, Math.max(bySource.get(m.source) ?? 0, m.confidence));
      let conf = 1;
      for (const v of bySource.values()) conf *= 1 - v;
      conf = Math.min(0.97, 1 - conf);

      // Center: keep a precise fix (GPS / geocoded rep) EXACTLY on its rep — never
      // blur a hard fix. But an estimate-only cluster is several independent rough
      // AI guesses of the same place; their confidence/precision-weighted centroid
      // sits closer to truth than any single model call (averages out per-call
      // error). Tighter, more-confident guesses pull harder (weight = conf/radius).
      let lat = c.rep.lat;
      let lon = c.rep.lon;
      if (c.rep.kind === "estimate" && c.members.length > 1) {
        let sw = 0;
        let slat = 0;
        let slon = 0;
        for (const mem of c.members) {
          const w = mem.confidence / Math.max(mem.radiusKm, 0.05);
          sw += w;
          slat += mem.lat * w;
          slon += mem.lon * w;
        }
        if (sw > 0) {
          lat = slat / sw;
          lon = slon / sw;
        }
      }
      return {
        lat,
        lon,
        label: c.rep.label,
        source: c.rep.source,
        confidence: conf,
        kind: c.rep.kind,
        radiusKm: c.rep.radiusKm,
        corroboration: bySource.size,
        sources: [...c.sources],
      } as GeoPoint;
    })
    .sort((a, b) => (b.corroboration ?? 1) - (a.corroboration ?? 1) || b.confidence - a.confidence);
}
