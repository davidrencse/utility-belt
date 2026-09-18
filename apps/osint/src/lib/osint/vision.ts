import sharp from "sharp";
import { imageMediaType, safeFetch } from "./util";

// Provider-agnostic vision client. Talks to any OpenAI-compatible chat endpoint
// that accepts image_url content parts. Swap providers via env only:
//
//   Groq (default, free):  VISION_API_KEY=gsk_...   (or GROQ_API_KEY)
//   Gemini (free tier):    VISION_API_KEY=...  VISION_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai  VISION_MODEL=gemini-2.0-flash
//   OpenRouter / others:   set the three vars accordingly

export const VISION_MAX_BYTES = 4 * 1024 * 1024; // most free tiers cap base64 images ~4MB

// Longest-side the model actually benefits from. Big enough to keep signs,
// plates and distant text legible; small enough to fit the byte cap at good
// quality. Override with VISION_MAX_DIM.
const VISION_MAX_DIM = Number(process.env.VISION_MAX_DIM) || 2560;

/**
 * Make an image the best possible INPUT for a vision API, then fit it under the
 * provider's ~4MB base64 cap. Real camera/phone photos are 5–12MB (over the cap
 * → silently rejected = the "No location found" bug); huge-dimension images get
 * crudely crushed by the provider's own downscale, smearing the fine detail
 * (signs, text, plates) that detection depends on. So we:
 *   - reprocess when over the byte cap OR larger than ~4k px on the long side,
 *   - resize to a clean longest side with Lanczos, then SHARPEN to restore the
 *     edge crispness a downscale removes,
 *   - encode JPEG with 4:4:4 chroma (no colour subsampling) so coloured small
 *     text/signage stays readable, stepping quality down until it fits.
 * EXIF GPS is read from the ORIGINAL buffer elsewhere, so reprocessing here is
 * fine. Modest images pass through untouched at full fidelity.
 */
// Four AI sources (geovision, scene, faces, refine) each prepare the SAME
// uploaded Buffer. Without memoization that's 4× the sharp decode→resize→sharpen
// →JPEG-encode of one photo (the loop can encode several times) plus 5× base64.
// Sources receive the same Buffer reference from ctx.images, so a WeakMap keyed
// on the Buffer collapses that to one prepare per image and auto-GCs after the
// request. Promise-valued so concurrent callers share the in-flight work.
const prepCache = new WeakMap<Buffer, Promise<{ data: Buffer; mediaType: string }>>();

export function prepareVisionImage(
  buffer: Buffer,
  filename: string,
): Promise<{ data: Buffer; mediaType: string }> {
  const hit = prepCache.get(buffer);
  if (hit) return hit;
  const p = prepareVisionImageUncached(buffer, filename);
  prepCache.set(buffer, p);
  return p;
}

async function prepareVisionImageUncached(
  buffer: Buffer,
  filename: string,
): Promise<{ data: Buffer; mediaType: string }> {
  let longest = 0;
  try {
    const meta = await sharp(buffer, { failOn: "none" }).metadata();
    longest = Math.max(meta.width || 0, meta.height || 0);
  } catch {
    // metadata failed — fall back to byte-size heuristic only
  }
  const overBytes = buffer.length > VISION_MAX_BYTES;
  const overDims = longest > 4000;
  if (!overBytes && !overDims) {
    return { data: buffer, mediaType: imageMediaType(filename) };
  }

  // .rotate() bakes in EXIF orientation so the model sees the photo upright.
  // Decode → rotate → resize(Lanczos) → sharpen ONCE into raw pixels, then only
  // the JPEG re-encode varies per quality step. The old loop re-ran the full
  // decode + resize + sharpen on every iteration (up to 4×); those are the
  // expensive ops — re-encoding from raw is the only part that needs to repeat.
  const width = Math.min(VISION_MAX_DIM, longest || VISION_MAX_DIM);
  try {
    const { data: raw, info } = await sharp(buffer, { failOn: "none" })
      .rotate()
      .resize({ width, height: width, fit: "inside", withoutEnlargement: true, kernel: "lanczos3" })
      .sharpen({ sigma: 0.6 })
      .raw()
      .toBuffer({ resolveWithObject: true });
    const rawOpts = { raw: { width: info.width, height: info.height, channels: info.channels } };
    for (let q = 90; q >= 45; q -= 12) {
      const out = await sharp(raw, rawOpts)
        .jpeg({ quality: q, chromaSubsampling: "4:4:4", mozjpeg: true })
        .toBuffer();
      if (out.length <= VISION_MAX_BYTES) return { data: out, mediaType: "image/jpeg" };
    }
  } catch {
    // unsupported/corrupt input — fall through to the aggressive-shrink last resort
  }
  // Last resort: aggressive shrink; if even decode failed, send original and let
  // the API surface the real error rather than silently dropping the image.
  try {
    const out = await sharp(buffer, { failOn: "none" })
      .rotate()
      .resize({ width: 1400, fit: "inside", withoutEnlargement: true })
      .sharpen({ sigma: 0.5 })
      .jpeg({ quality: 48 })
      .toBuffer();
    return { data: out, mediaType: "image/jpeg" };
  } catch {
    return { data: buffer, mediaType: imageMediaType(filename) };
  }
}

// The prepared Buffer is shared across all sources (prepareVisionImage memoizes),
// so its base64 data URL is identical every call — encode it once per image.
const dataUrlCache = new WeakMap<Buffer, string>();
function dataUrlFor(prepared: { data: Buffer; mediaType: string }): string {
  const hit = dataUrlCache.get(prepared.data);
  if (hit) return hit;
  const url = `data:${prepared.mediaType};base64,${prepared.data.toString("base64")}`;
  dataUrlCache.set(prepared.data, url);
  return url;
}

export interface VisionConfig {
  baseUrl: string;
  apiKey: string;
  model: string;
}

export function visionConfig(keys: Record<string, string | undefined>): VisionConfig | null {
  const apiKey = keys.VISION_API_KEY;
  if (!apiKey) return null;
  return {
    baseUrl: (process.env.VISION_BASE_URL || "https://api.groq.com/openai/v1").replace(/\/$/, ""),
    apiKey,
    model: process.env.VISION_MODEL || "meta-llama/llama-4-scout-17b-16e-instruct",
  };
}

function extractJson<T>(text: string): T | null {
  try {
    return JSON.parse(text) as T;
  } catch {
    const a = text.indexOf("{");
    const b = text.lastIndexOf("}");
    if (a >= 0 && b > a) {
      try {
        return JSON.parse(text.slice(a, b + 1)) as T;
      } catch {
        return null;
      }
    }
    return null;
  }
}

/** Send an image + prompt, expect a JSON object back, parse it. Throws on failure. */
export async function analyzeImageJson<T>(opts: {
  buffer: Buffer;
  filename: string;
  prompt: string;
  cfg: VisionConfig;
  signal?: AbortSignal;
}): Promise<T> {
  const { buffer, filename, prompt, cfg, signal } = opts;
  const prepared = await prepareVisionImage(buffer, filename);
  const dataUrl = dataUrlFor(prepared);

  const res = await safeFetch(
    `${cfg.baseUrl}/chat/completions`,
    {
      method: "POST",
      headers: { authorization: `Bearer ${cfg.apiKey}`, "content-type": "application/json" },
      body: JSON.stringify({
        model: cfg.model,
        temperature: 0.2,
        // Rich responses — multi-face attributes, many clues, transcribed text,
        // and per-feature bounding boxes (regions[]) — readily exceed 2k tokens;
        // truncation produces unparseable JSON (= a silently failed detection), so
        // keep generous headroom.
        max_tokens: 4096,
        messages: [
          {
            role: "user",
            content: [
              { type: "text", text: prompt },
              { type: "image_url", image_url: { url: dataUrl } },
            ],
          },
        ],
      }),
    },
    25000,
    signal,
  );

  if (!res.ok) {
    const msg = await res.text().catch(() => "");
    throw new Error(`vision ${cfg.model} ${res.status}: ${msg.slice(0, 200)}`);
  }
  const j = (await res.json()) as { choices?: { message?: { content?: string } }[] };
  const content = j.choices?.[0]?.message?.content || "";
  const parsed = extractJson<T>(content);
  if (!parsed) throw new Error("vision model returned unparseable JSON");
  return parsed;
}
