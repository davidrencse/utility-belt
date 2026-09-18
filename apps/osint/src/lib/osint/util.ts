import type { Box, Entity, EntityType } from "./types";

/**
 * Validate an AI-returned bounding box: all four corners must be finite, the box
 * must have positive size and sit (roughly) within the image. Clamps into [0,1]
 * so an overlay never escapes the frame. Returns undefined for a junk box so the
 * caller can simply drop it (no overlay) rather than render garbage.
 */
export function cleanBox(b: Partial<Box> | undefined): Box | undefined {
  if (!b) return undefined;
  const { x, y, w, h } = b;
  if ([x, y, w, h].some((n) => typeof n !== "number" || !Number.isFinite(n))) return undefined;
  if (w! <= 0 || h! <= 0 || x! < -0.05 || y! < -0.05 || x! > 1.05 || y! > 1.05) return undefined;
  const clamp = (n: number) => Math.max(0, Math.min(1, n));
  return { x: clamp(x!), y: clamp(y!), w: clamp(w!), h: clamp(h!) };
}

export function entity(
  type: EntityType,
  value: string,
  source: string,
  confidence = 0.7,
  extra: Partial<Entity> = {},
): Entity {
  const v = value.trim();
  return {
    id: `${type}:${v.toLowerCase()}`,
    type,
    value: v,
    source,
    confidence,
    ...extra,
  };
}

/** Reject garbage entity values (empty, malformed) before they enter the graph. */
export function isValidEntity(e: Entity): boolean {
  const v = e.value.trim();
  if (!v || v === "." || v.length > 2048) return false;
  return true;
}

/**
 * Bounded-concurrency runner. Returns a function that queues async work and
 * never lets more than `max` run at once. Used to throttle the engine's source
 * fan-out and to keep geocoding within OSM Nominatim's politeness limits.
 */
export function createLimiter(max: number) {
  let active = 0;
  const queue: Array<() => void> = [];
  const pump = () => {
    if (active >= max) return;
    const run = queue.shift();
    if (run) {
      active++;
      run();
    }
  };
  return function run<T>(fn: () => Promise<T>): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      queue.push(() =>
        fn()
          .then(resolve, reject)
          .finally(() => {
            active--;
            pump();
          }),
      );
      pump();
    });
  };
}

const DEFAULT_TIMEOUT = 8000;

/**
 * fetch with a timeout, merged with an optional upstream abort signal.
 *
 * The timeout bounds the WHOLE request, including reading the body: the signal
 * stays armed after headers arrive, so a provider that sends headers and then
 * stalls mid-body can't hang `res.json()` / `res.text()` until the route's
 * maxDuration. Aborting after the body has been fully read is a no-op.
 */
export async function safeFetch(
  url: string,
  init: RequestInit = {},
  timeoutMs = DEFAULT_TIMEOUT,
  upstream?: AbortSignal,
): Promise<Response> {
  const ctrl = new AbortController();
  const onAbort = () => ctrl.abort();
  const cleanup = () => {
    clearTimeout(timer);
    upstream?.removeEventListener("abort", onAbort);
  };
  const timer = setTimeout(() => {
    ctrl.abort();
    cleanup();
  }, timeoutMs);
  upstream?.addEventListener("abort", onAbort);
  try {
    return await fetch(url, {
      ...init,
      signal: ctrl.signal,
      headers: {
        "user-agent":
          "image-geolocator/0.1 (+research; respects-robots; public-sources-only)",
        ...(init.headers || {}),
      },
    });
  } catch (err) {
    cleanup(); // no body to guard
    throw err;
  }
}

export function imageMediaType(name: string): string {
  const ext = name.toLowerCase().split(".").pop() || "";
  return (
    {
      jpg: "image/jpeg",
      jpeg: "image/jpeg",
      png: "image/png",
      webp: "image/webp",
      gif: "image/gif",
      bmp: "image/bmp",
    }[ext] || "image/jpeg"
  );
}
