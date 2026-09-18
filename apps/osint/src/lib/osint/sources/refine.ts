import type { Source, Finding, Entity } from "../types";
import { entity } from "../util";
import { analyzeImageJson, visionConfig } from "../vision";

// Detection layer: COARSE → FINE REFINEMENT. The other layers settle on an
// APPROXIMATE AREA (a city/region). This layer takes that area as a prior and
// re-examines the SAME photo to zone in and pin the EXACT spot — specific
// street/intersection/building/vantage point — at street-level precision.
//
// It fires only on the geovision "subject" estimate (which carries the source
// image + coarse area in its meta), so there's exactly one refine pass per image.
// Its output is tagged kind:"geocoded" + refined:true so it never re-triggers
// itself (no loop) and ranks above the coarse estimate it sharpened.

const REFINE_PROMPT = (
  area: string,
  lat: number,
  lon: number,
) => `An expert OSINT analyst placed this photo APPROXIMATELY here: ${area} (~${lat.toFixed(4)}, ${lon.toFixed(4)}).
That is only a rough area. Your job: ZONE IN and pin the EXACT spot the CAMERA STOOD, to street level, using fine-grained visible detail you may have skipped before:
- exact storefront / business names and house/street numbers
- the specific building, monument face, or street furniture in frame
- intersection / cross-streets, signage, bus-stop or station names
- precise vantage: which side of the street/square/river, looking which way
PERSPECTIVE & BRIDGES — pin the PHOTOGRAPHER, not the structure's midpoint:
- Use vanishing points, line convergence and foreshortening to fix the standpoint and view direction.
- For a bridge/street/pier/coastline, work out which END is in the foreground and whether the shot is taken FROM ON the structure (pin the spot on the deck/path) or from a vantage OFF it (riverbank, embankment, an adjacent bridge) looking across — and pin THAT vantage.
- Long structures: the camera is at the near end / the offset viewpoint, not the centre of the span.
Return coordinates for the camera standpoint. Use your geographic knowledge of THIS area to convert these details into precise coordinates. Stay within (or very near) the given area unless a detail proves it wrong.
Respond with ONLY a JSON object, no prose, no code fences:
{"refined":bool,"lat":number|null,"lon":number|null,"exactPlace":string|null,"address":string|null,"crossStreets":string|null,"precisionM":number|null,"confidence":number,"reasoning":string}`;

interface RefineOut {
  refined?: boolean;
  lat?: number | null;
  lon?: number | null;
  exactPlace?: string | null;
  address?: string | null;
  crossStreets?: string | null;
  precisionM?: number | null;
  confidence?: number;
  reasoning?: string;
}

const refineSource: Source = {
  id: "refine",
  label: "Pinpoint Refinement (AI)",
  handles: ["location"],
  requiresKey: "VISION_API_KEY",
  async run(e, ctx) {
    const m = e.meta as
      | { lat?: number; lon?: number; kind?: string; image?: string; area?: string; refined?: boolean }
      | undefined;
    // Only sharpen the primary coarse visual estimate, once, and never re-refine.
    if (
      e.source !== "geovision" ||
      m?.kind !== "estimate" ||
      m?.refined ||
      !m?.image ||
      typeof m?.lat !== "number" ||
      typeof m?.lon !== "number"
    ) {
      return [];
    }
    const buf = ctx.images?.[m.image];
    const cfg = visionConfig(ctx.keys);
    if (!buf || !cfg) return [];

    const area = m.area || e.value;
    const o = await analyzeImageJson<RefineOut>({
      buffer: buf,
      filename: m.image,
      prompt: REFINE_PROMPT(area, m.lat, m.lon),
      cfg,
      signal: ctx.signal,
    });

    if (!o.refined || typeof o.lat !== "number" || typeof o.lon !== "number") {
      return [
        {
          source: "refine",
          image: m.image,
          title: `Could not sharpen ${area} beyond the area estimate`,
          severity: "info",
          detail: o.reasoning,
        },
      ];
    }

    const conf = Math.min(0.92, typeof o.confidence === "number" ? o.confidence : 0.5);
    // precision radius from the model's own estimate, floored/capped to sane bounds
    const radiusKm = Math.min(3, Math.max(0.05, (typeof o.precisionM === "number" ? o.precisionM : 300) / 1000));
    const label = o.exactPlace || o.address || `refined: ${area}`;

    const ent: Entity = entity(
      "location",
      `${label} [${o.lat.toFixed(4)}, ${o.lon.toFixed(4)}]`,
      "refine",
      conf,
      {
        label: `pinpoint: ${label}`,
        meta: {
          lat: o.lat,
          lon: o.lon,
          radiusKm,
          kind: "geocoded", // precise tier; also prevents re-refinement
          refined: true,
          map: `https://www.google.com/maps?q=${o.lat},${o.lon}`,
        },
      },
    );

    return [
      {
        source: "refine",
        image: m.image,
        title: `Pinpointed: ${label} (${Math.round(conf * 100)}%)`,
        severity: conf >= 0.7 ? "high" : "medium",
        url: `https://www.google.com/maps?q=${o.lat},${o.lon}`,
        data: {
          fromArea: area,
          exactPlace: o.exactPlace || undefined,
          address: o.address || undefined,
          crossStreets: o.crossStreets || undefined,
          coords: `${o.lat}, ${o.lon}`,
          precisionM: typeof o.precisionM === "number" ? o.precisionM : undefined,
          reasoning: o.reasoning,
          model: cfg.model,
          note: "Second-pass zoom from approximate area to exact spot — verify before relying on it.",
        },
        entities: [ent],
      } as Finding,
    ];
  },
};

export default refineSource;
