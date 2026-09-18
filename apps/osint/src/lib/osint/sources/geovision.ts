import type { Source, Finding, Entity, Severity, Box } from "../types";
import { entity, cleanBox } from "../util";
import { analyzeImageJson, visionConfig } from "../vision";
import { destinationPoint, compass8 } from "../geo";

// Visual geolocation: estimate where a photo was taken from PIXEL CONTENT alone
// (works even with zero metadata). Provider-agnostic — see ../vision.ts.
// EXIF GPS and IPTC/XMP tags are handled by `exif`; geocoding by `geocode`.

const PROMPT = `You are an elite OSINT geolocation analyst (GeoGuessr world-champion level + image forensics).
GOAL: pin where this photo was taken from VISIBLE CONTENT ALONE. Treat it as solvable — even a featureless-looking shot leaks region-level cues. ALWAYS commit to a best guess; never answer "could be anywhere".

SCAN THE ENTIRE FRAME, not just the obvious subject. Most location signal hides in the BACKGROUND and at the EDGES:
- Background & periphery: distant skyline, hills/mountains, coastline, what's through windows/doorways, far-off signs, reflections in glass/water/mirrors, blurry text — zoom your attention there deliberately.
- Architecture: building style/era, construction material (brick/render/timber/concrete), roof pitch & material, window & balcony style, chimneys, fences, house numbers.
- Text & script: language, alphabet, business/street names, fonts, phone-number format, domain TLDs (.de/.uk/.jp), price currency.
- Roads & infrastructure: which side cars drive, lane markings, sign shapes/colours, bollards, guardrails, traffic-light style, utility poles & wiring, fire hydrants, manhole covers, power-outlet shapes.
- Vehicles: license-plate shape/colour/format, common car models/brands for the region, bus/taxi livery.
- Nature & sky: vegetation type, crops, soil colour, climate cues, terrain, snow, sun elevation & shadow direction (hemisphere/time), star field if night.
- Culture & symbols: flags, emblems, sports clubs, religious buildings, regional chain brands, clothing, road-marking colour conventions.
Cross-reference several independent cues before committing; state the strongest ones in clues[].

Then commit to the single most likely location with its lat/lon — this lat/lon is the SUBJECT/scene the lens points at (the landmark, building, or street center in frame), NOT necessarily where the photographer stood. If you can only narrow to a city/region/country, give that center and lower confidence accordingly — but still output coordinates.
Then reason about CAMERA GEOMETRY using PERSPECTIVE — vanishing points, line convergence, foreshortening, and relative sizes tell you viewing direction and depth. Estimate:
- camera.bearingDeg: compass direction the camera POINTS, from photographer TOWARD the subject (0=N, 90=E, 180=S, 270=W). Infer from which face/side of the subject is shown, shadow/sun direction, and how parallel lines converge.
- camera.distanceM: horizontal distance (metres) from photographer to the part of the subject NEAREST the camera (a close sign ≈ 5, a building across a plaza ≈ 80, a skyline across a bay ≈ 2000). null if truly unknown.
- camera.viewpoint: short text, e.g. "on the embankment, across the river, looking NE".
- camera.onSubject: TRUE if the photographer stands ON/INSIDE the subject (on a bridge deck, in the street, on a pier) looking ALONG it; FALSE if viewing it from OUTSIDE (from a riverbank, plaza, or another bridge).
- camera.heightM: height of the LENS above the local ground in metres — handheld eye-level ≈ 1.6, raised terrace / upper floor ≈ 3–30, hill/overlook higher, rooftop/observation deck tens of metres, aerial/drone ≈ 30–150. Judge from the downward/upward look angle and horizon position. Use 1.6 if it looks like a normal standing shot, null if impossible to tell.

ELONGATED / LINEAR SUBJECTS (bridge, street, pier, wall, railway, river, coastline, colonnade) — handle perspective carefully:
- Set lat/lon to the NEAR / foreground part of the structure actually closest to the camera in frame, NOT the whole-structure midpoint. A long bridge shot from one end is geolocated at THAT end, not mid-span.
- A bridge/tower seen across water: onSubject=false, distanceM = the real standoff to the near edge, bearing = camera→structure.
- A shot taken FROM the bridge/street looking along it: onSubject=true, distanceM small, bearing = the line of sight down the structure.
If the shot is a flat document/screenshot/close-up with no spatial depth, set distanceM null and onSubject false.
Calibrate confidence to how tight your fix is: ~0.9+ exact street/landmark, ~0.6 right city, ~0.4 right region, ~0.2 only country/continent. Set geolocatable=false ONLY for flat documents/screenshots/plain-studio shots with zero environmental cues.
Also transcribe ALL readable text (signs, shopfronts, banners, street/transit signs, plates, posters, faint/background text) into visibleText[]. For any text that could pin a real place, build a SEARCHABLE place query combining the business/street/landmark name with the city/area/country you inferred (e.g. "Cafe Central, Vienna") and list these in placeQueries[]. List named, searchable landmarks/businesses in landmarks[].
Then locate the specific ON-IMAGE features that drove your geolocation and return them in regions[] — the buildings, landmarks, monuments, signs/text, vehicles, and distinctive terrain you actually used as evidence. For each give:
- label: short name of the thing (e.g. "Gothic spire", "street sign: Rue de Rivoli", "red double-decker bus")
- kind: one of "building" | "landmark" | "sign" | "vehicle" | "terrain" | "object"
- box: bounding box as fractions of image size {x,y,w,h}, x,y = TOP-LEFT corner, each 0..1 (x+w ≤ 1, y+h ≤ 1)
- note: one sentence on what this feature reveals about the location
Only include features you can actually see and box; omit anything you cannot localize.
Do NOT identify specific private individuals.
Respond with ONLY a JSON object, no prose, no code fences:
{"geolocatable":bool,"city":string|null,"region":string|null,"country":string|null,"lat":number|null,"lon":number|null,"confidence":number,"camera":{"bearingDeg":number|null,"distanceM":number|null,"onSubject":bool,"heightM":number|null,"viewpoint":string|null},"reasoning":string,"clues":string[],"visibleText":string[],"placeQueries":string[],"landmarks":string[],"regions":[{"label":string,"kind":string,"box":{"x":number,"y":number,"w":number,"h":number},"note":string}],"alternatives":[{"place":string,"lat":number|null,"lon":number|null}]}`;

interface GeoOut {
  geolocatable?: boolean;
  city?: string | null;
  region?: string | null;
  country?: string | null;
  lat?: number | null;
  lon?: number | null;
  confidence?: number;
  camera?: { bearingDeg?: number | null; distanceM?: number | null; onSubject?: boolean; heightM?: number | null; viewpoint?: string | null };
  reasoning?: string;
  clues?: string[];
  visibleText?: string[];
  placeQueries?: string[];
  landmarks?: string[];
  regions?: { label?: string; kind?: string; box?: Partial<Box>; note?: string }[];
  alternatives?: { place: string; lat: number | null; lon: number | null }[];
}

const REGION_KINDS = new Set(["building", "landmark", "sign", "vehicle", "terrain", "object"]);

const sevFor = (c: number): Severity => (c >= 0.7 ? "high" : c >= 0.4 ? "medium" : "low");

function point(
  place: string,
  lat: number,
  lon: number,
  label: string,
  conf: number,
  radiusKm: number,
): Entity {
  return entity("location", `${place} (≈${lat.toFixed(3)}, ${lon.toFixed(3)})`, "geovision", conf, {
    label,
    meta: { lat, lon, radiusKm, kind: "estimate", estimate: true },
  });
}

const geovisionSource: Source = {
  id: "geovision",
  label: "Visual Geolocation (AI)",
  handles: ["image"],
  requiresKey: "VISION_API_KEY",
  async run(e, ctx) {
    const buf = ctx.images?.[e.value];
    const cfg = visionConfig(ctx.keys);
    if (!buf || !cfg) return [];
    // Large photos are downscaled inside analyzeImageJson (see prepareVisionImage)
    // so full-resolution camera images are still analyzed, not rejected.

    const o = await analyzeImageJson<GeoOut>({
      buffer: buf,
      filename: e.value,
      prompt: PROMPT,
      cfg,
      signal: ctx.signal,
    });

    if (!o.geolocatable) {
      return [
        { source: "geovision", image: e.value, title: `No visual location cues in ${e.value}`, severity: "info", detail: o.reasoning },
      ];
    }

    const conf = typeof o.confidence === "number" ? o.confidence : 0.3;
    const place = [o.city, o.region, o.country].filter(Boolean).join(", ") || "unknown";
    // The visual-estimate coords, if any — handed to every text entity below as a
    // geocoding bias (`near`) so ambiguous landmark/sign names resolve to the place
    // ACTUALLY shown in the photo, not a same-named feature on another continent.
    const near =
      typeof o.lat === "number" && typeof o.lon === "number" ? { lat: o.lat, lon: o.lon } : null;
    // accuracy scales with how specific the AI got: street/city < region < country
    const estRadius = o.city ? 15 : o.region ? 80 : 500;
    const entities: Entity[] = [];
    let cameraPoint: { lat: number; lon: number; distM: number; side: string } | null = null;
    if (typeof o.lat === "number" && typeof o.lon === "number") {
      const subj = point(place, o.lat, o.lon, "subject in view (AI)", Math.min(conf, 0.8), estRadius);
      // Carry the source image + coarse area so the `refine` layer can re-examine
      // this photo and zoom from approximate-area to exact spot.
      Object.assign(subj.meta as Record<string, unknown>, { image: e.value, area: place });
      entities.push(subj);

      // Camera-position correction. o.lat/o.lon is the SUBJECT the lens points at,
      // not where the photographer stood. If the model estimated the look bearing
      // (camera→subject) and the distance to it, project backward along the
      // reverse bearing to recover the photographer's ground position. Only do
      // this for a meaningful, bounded offset and when we have a landmark/city-
      // level fix — projecting off a vague country guess is noise.
      const cam = o.camera;
      const bearing = typeof cam?.bearingDeg === "number" ? cam.bearingDeg : null;
      const distM = typeof cam?.distanceM === "number" ? cam.distanceM : null;
      // If the photographer stands ON the subject (on the bridge/street/pier), the
      // subject foreground point already IS the camera standpoint — don't project a
      // phantom standpoint 180° across the structure. Only offset when viewing it
      // from outside, with a meaningful standoff and a landmark/city-level fix.
      if (!cam?.onSubject && bearing != null && distM != null && distM > 30 && distM < 50000 && (o.city || o.region)) {
        const dKm = distM / 1000;
        // photographer sits opposite the look direction, dKm from the subject
        const [clat, clon] = destinationPoint(o.lat, o.lon, (bearing + 180) % 360, dKm);
        const side = compass8((bearing + 180) % 360); // which side of subject the camera is on
        // camera ground position is less certain than the subject: bearing ±~30°
        // and range ±~50% both blur it. Floor at the subject's own radius.
        const camRadius = Math.max(estRadius * 0.4, dKm * 0.6, 0.05);
        const distLabel = distM >= 1000 ? `${(distM / 1000).toFixed(1)}km` : `${Math.round(distM)}m`;
        entities.push(
          entity(
            "location",
            `camera position (≈${clat.toFixed(3)}, ${clon.toFixed(3)})`,
            "geovision",
            Math.min(conf * 0.85, 0.75),
            {
              label: `photographer ~${distLabel} ${side} of subject`,
              meta: { lat: clat, lon: clon, radiusKm: camRadius, kind: "estimate", estimate: true, camera: true },
            },
          ),
        );
        cameraPoint = { lat: clat, lon: clon, distM, side };
      }
    } else if (place !== "unknown") {
      // Model named a place but returned no coordinates — hand the text to the
      // geocoder so it still becomes a map point instead of silently vanishing
      // ("NO FIX" despite a clearly named location).
      entities.push(
        entity("location", place, "geovision", Math.min(conf, 0.7), { label: "visual estimate (AI)" }),
      );
    }
    for (const alt of o.alternatives || []) {
      if (typeof alt?.lat === "number" && typeof alt?.lon === "number") {
        entities.push(point(alt.place, alt.lat, alt.lon, "alternative estimate", 0.3, 80));
      } else if (alt?.place && String(alt.place).trim().length > 2) {
        // no coords on the alternative either — let geocode resolve the name
        entities.push(
          entity("location", String(alt.place).trim(), "geovision", 0.3, {
            label: "alternative estimate",
            meta: near ? { near } : undefined,
          }),
        );
      }
    }
    // feed named landmarks/businesses back into the pipeline (geocode -> map).
    // Qualify bare landmark names with the inferred locality so generic names
    // (e.g. "Big Ben" also being a peak on Heard Island, AU) geocode to the
    // place actually shown in the photo, not a same-named feature elsewhere.
    const locality = [o.city, o.region, o.country].filter(Boolean).join(", ");
    for (const lm of o.landmarks || []) {
      const v = String(lm).trim();
      if (v.length <= 2) continue;
      const lc = v.toLowerCase();
      const hasContext = [o.city, o.region, o.country].some(
        (p) => p && lc.includes(p.toLowerCase()),
      );
      const q = locality && !hasContext ? `${v}, ${locality}` : v;
      entities.push(
        entity("location", q, "geovision", 0.6, {
          label: "landmark in photo",
          meta: near ? { near } : undefined,
        }),
      );
    }

    // Sign/text place queries (formerly the separate `ocr` source — merged here so
    // one vision call does both the holistic estimate and text extraction). Emit
    // them under source "ocr" so geo.ts fusion still counts a text-derived geocode
    // as INDEPENDENT corroboration of the visual estimate, not the same source.
    const seenQ = new Set<string>();
    for (const pq of o.placeQueries || []) {
      const q = String(pq).trim();
      const lc = q.toLowerCase();
      if (q.length > 2 && !seenQ.has(lc)) {
        seenQ.add(lc);
        entities.push(
          entity("location", q, "ocr", 0.5, {
            label: `sign: ${q.slice(0, 40)}`,
            meta: near ? { near } : undefined,
          }),
        );
      }
    }

    return [
      {
        source: "geovision",
        image: e.value,
        title: `Visual estimate: ${place} (${Math.round(conf * 100)}%)`,
        severity: sevFor(conf),
        url:
          typeof o.lat === "number" && typeof o.lon === "number"
            ? `https://www.google.com/maps?q=${o.lat},${o.lon}`
            : undefined,
        data: {
          estimate: place,
          coords: typeof o.lat === "number" ? `${o.lat}, ${o.lon}` : undefined,
          subjectNote: cameraPoint ? "coords above = subject in frame, not the camera" : undefined,
          cameraPosition: cameraPoint
            ? `${cameraPoint.lat.toFixed(4)}, ${cameraPoint.lon.toFixed(4)} (~${
                cameraPoint.distM >= 1000
                  ? `${(cameraPoint.distM / 1000).toFixed(1)}km`
                  : `${Math.round(cameraPoint.distM)}m`
              } ${cameraPoint.side} of subject)`
            : undefined,
          viewpoint: o.camera?.viewpoint || undefined,
          cameraHeightM: typeof o.camera?.heightM === "number" ? o.camera.heightM : undefined,
          confidence: conf,
          reasoning: o.reasoning,
          clues: o.clues,
          visibleText: o.visibleText,
          landmarks: o.landmarks,
          // On-image evidence with bounding boxes (best-effort; only well-formed
          // boxes survive so the client can overlay them on the photo).
          regions: (o.regions || [])
            .map((r) => {
              const box = cleanBox(r.box);
              if (!box || !r.label) return null;
              const kind = REGION_KINDS.has(String(r.kind)) ? String(r.kind) : "object";
              return { label: String(r.label).slice(0, 80), kind, box, note: r.note ? String(r.note) : undefined };
            })
            .filter(Boolean),
          alternatives: (o.alternatives || []).map((a) => a.place),
          model: cfg.model,
          note: "AI inference from image content — verify before relying on it.",
        },
        entities,
      } as Finding,
    ];
  },
};

export default geovisionSource;
