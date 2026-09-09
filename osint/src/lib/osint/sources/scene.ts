import type { Source, Finding, Entity } from "../types";
import { entity } from "../util";
import { analyzeImageJson, visionConfig } from "../vision";

// Detection layer: SCENE / ARCHITECTURE classifier. Deliberately ignores any
// single famous landmark and instead reads the BACKGROUND ENVIRONMENT — building
// style, road infrastructure, driving side, vegetation/biome, terrain, sky/sun,
// utility poles, plate norms — to place the photo by REGION. This catches photos
// with no landmark and no readable text, where only the "vibe" of the scene
// betrays the country/region. Emits a coarse, wide-radius estimate that fuses
// with the other layers (corroboration when they agree, fallback when they don't).

const PROMPT = `You are a geographic scene classifier (GeoGuessr "meta" expert). IGNORE any single famous landmark. Read only the BACKGROUND ENVIRONMENT to place this photo by region:
- Architecture: style, era, building materials, roof shape/material, window & balcony patterns, fences, house numbering.
- Roads & infrastructure: which side traffic drives, lane-marking colour, sign shapes, bollards, guardrails, traffic-light style, utility poles & overhead wiring, hydrants, manhole covers, power-socket shapes.
- Nature: vegetation/biome, crops, soil colour, terrain, climate cues, snow, sun elevation & shadow direction (hemisphere).
- Vehicles & plates: common car models, plate shape/colour, taxi/bus livery.
- Incidental script/language of any non-landmark text.
Weigh several signals together, then commit to ONE best region with a representative CENTER coordinate. Always give your best guess even if broad.
Respond with ONLY a JSON object, no prose, no code fences:
{"regionGuessable":bool,"country":string|null,"region":string|null,"drivingSide":"left"|"right"|"unknown","biome":string|null,"architecture":string|null,"lat":number|null,"lon":number|null,"confidence":number,"signals":string[]}`;

interface SceneOut {
  regionGuessable?: boolean;
  country?: string | null;
  region?: string | null;
  drivingSide?: string;
  biome?: string | null;
  architecture?: string | null;
  lat?: number | null;
  lon?: number | null;
  confidence?: number;
  signals?: string[];
}

const sceneSource: Source = {
  id: "scene",
  label: "Scene / Architecture Region (AI)",
  handles: ["image"],
  requiresKey: "VISION_API_KEY",
  async run(e, ctx) {
    const buf = ctx.images?.[e.value];
    const cfg = visionConfig(ctx.keys);
    if (!buf || !cfg) return [];

    const o = await analyzeImageJson<SceneOut>({
      buffer: buf,
      filename: e.value,
      prompt: PROMPT,
      cfg,
      signal: ctx.signal,
    });

    if (!o.regionGuessable) {
      return [{ source: "scene", image: e.value, title: `No regional cues in ${e.value}`, severity: "info" }];
    }

    const conf = typeof o.confidence === "number" ? o.confidence : 0.25;
    const place = [o.region, o.country].filter(Boolean).join(", ") || o.country || "unknown region";
    // scene reads are coarse by design: region-level center, big accuracy radius.
    const radiusKm = o.region ? 120 : 400;
    const entities: Entity[] = [];
    if (typeof o.lat === "number" && typeof o.lon === "number") {
      entities.push(
        entity("location", `${place} (≈${o.lat.toFixed(2)}, ${o.lon.toFixed(2)})`, "scene", Math.min(conf, 0.6), {
          label: "scene/architecture region",
          meta: { lat: o.lat, lon: o.lon, radiusKm, kind: "estimate", estimate: true },
        }),
      );
    } else if (place !== "unknown region") {
      // no coords from the model — let geocode resolve the named region
      entities.push(
        entity("location", place, "scene", Math.min(conf, 0.5), { label: "scene/architecture region" }),
      );
    }

    return [
      {
        source: "scene",
        image: e.value,
        title: `Scene region: ${place} (${Math.round(conf * 100)}%)`,
        severity: conf >= 0.5 ? "medium" : "low",
        data: {
          country: o.country || undefined,
          region: o.region || undefined,
          drivingSide: o.drivingSide,
          biome: o.biome || undefined,
          architecture: o.architecture || undefined,
          signals: o.signals,
          model: cfg.model,
          note: "Region inferred from background/architecture, not a specific landmark — coarse by design.",
        },
        entities,
      } as Finding,
    ];
  },
};

export default sceneSource;
