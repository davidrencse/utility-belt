import type {
  Entity,
  Finding,
  GeolocateResult,
  Source,
  SourceContext,
} from "./types";

import { buildGeo, attachElevation } from "./geo";
import { entity as makeEntity, isValidEntity, createLimiter } from "./util";

import exif from "./sources/exif";
import geovision from "./sources/geovision";
import scene from "./sources/scene";
import refine from "./sources/refine";
import geocode from "./sources/geocode";
import reverse from "./sources/reverse";
import instagram from "./sources/instagram";
import faces from "./sources/faces";

// Geolocation runs as layered, independent detectors that fuse in geo.ts, in a
// coarse → fine cascade:
//   1. exif      — embedded GPS + IPTC/XMP place tags (metadata)
//   2. geovision — holistic AI visual estimate + landmarks + sign/text place
//                  queries + camera geometry (one vision call; text extraction
//                  was merged in from the former standalone `ocr` source)
//   3. scene     — background architecture/biome/driving-side → region
//   4. geocode   — resolves named places from the layers above into coordinates
//   5. refine    — second AI pass seeded with the coarse area → exact spot
// reverse + instagram add corroboration links; faces is attribute-only.
export const SOURCES: Source[] = [exif, geovision, scene, refine, geocode, reverse, instagram, faces];

// Global cap on concurrent source runs so a multi-image upload doesn't fan out
// into hundreds of simultaneous outbound fetches.
const MAX_CONCURRENT_RUNS = 12;

export interface RunOptions {
  /** filename -> buffer for uploaded images */
  images: Record<string, Buffer>;
  signal?: AbortSignal;
}

function keysFromEnv(): Record<string, string | undefined> {
  return {
    // Vision provider key — VISION_API_KEY wins, GROQ_API_KEY is the default fallback.
    VISION_API_KEY: process.env.VISION_API_KEY || process.env.GROQ_API_KEY,
  };
}

export async function geolocate(opts: RunOptions): Promise<GeolocateResult> {
  const startedAt = new Date();
  const ctx: SourceContext = {
    keys: keysFromEnv(),
    images: opts.images,
    signal: opts.signal,
  };

  const entities = new Map<string, Entity>();
  const findings: Finding[] = [];
  const errors: GeolocateResult["errors"] = [];
  const skipped: GeolocateResult["skipped"] = [];

  // image entities from uploads
  for (const fname of Object.keys(opts.images)) {
    const e = makeEntity("image", fname, "input", 1.0);
    entities.set(e.id, e);
  }

  const ran = new Set<string>(); // `${sourceId}::${entityId}` dedupe
  const limit = createLimiter(MAX_CONCURRENT_RUNS);
  const pending = new Set<Promise<void>>();

  // Reactive dispatch: the moment a source emits a new entity we schedule its
  // downstream sources immediately — no barrier. So fast EXIF place tags get
  // geocoded while the slow AI vision call is still in flight, and the leaf
  // reverse-image upload never blocks the map-producing path.
  function schedule(ent: Entity) {
    for (const src of SOURCES) {
      if (!src.handles.includes(ent.type)) continue;
      const tag = `${src.id}::${ent.id}`;
      if (ran.has(tag)) continue;
      ran.add(tag);

      if (src.requiresKey && !ctx.keys[src.requiresKey]) {
        skipped.push({ source: src.label, key: src.requiresKey });
        continue;
      }

      const job = limit(() => src.run(ent, ctx))
        .then((fs) => {
          for (const f of fs) {
            findings.push(f);
            for (const ne of f.entities || []) {
              if (!isValidEntity(ne)) continue;
              if (!entities.has(ne.id)) {
                entities.set(ne.id, ne);
                schedule(ne); // feed discoveries back in immediately
              }
            }
          }
        })
        .catch((err: unknown) => {
          errors.push({
            source: src.id,
            entity: ent.id,
            message: err instanceof Error ? err.message : String(err),
          });
        });

      pending.add(job);
      job.finally(() => pending.delete(job));
    }
  }

  for (const ent of [...entities.values()]) schedule(ent);
  // Drain: schedule() may add new jobs while we await, so loop until quiescent.
  while (pending.size) await Promise.allSettled([...pending]);

  // dedupe skipped
  const seenSkip = new Set<string>();
  const skippedUniq = skipped.filter((s) => {
    const k = `${s.source}:${s.key}`;
    if (seenSkip.has(k)) return false;
    seenSkip.add(k);
    return true;
  });

  const entityList = [...entities.values()].sort((a, b) => b.confidence - a.confidence);
  const geo = buildGeo(entityList);
  // Enrich fused points with ground elevation (best-effort, one batched call).
  await attachElevation(geo, opts.signal);

  const finishedAt = new Date();
  return {
    images: Object.keys(opts.images),
    geo,
    entities: entityList,
    // Strip each finding's `entities`: they exist only to feed the engine's
    // reactive pivoting (schedule()), are a full duplicate of the entities
    // already returned at top level (with their meta), and are never read by the
    // client — shipping them just bloats the response JSON.
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    findings: findings.map(({ entities, ...f }) => f),
    skipped: skippedUniq,
    errors,
    startedAt: startedAt.toISOString(),
    finishedAt: finishedAt.toISOString(),
    durationMs: finishedAt.getTime() - startedAt.getTime(),
  };
}
