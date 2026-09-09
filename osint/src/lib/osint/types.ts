// Core types for the Image Geolocator engine

export type EntityType = "image" | "location" | "unknown";

export type Severity = "info" | "low" | "medium" | "high";

export interface Entity {
  /** stable id: `${type}:${value}` lowercased */
  id: string;
  type: EntityType;
  value: string;
  label?: string;
  /** 0..1 — how sure we are this entity is real / relevant */
  confidence: number;
  /** which source produced it */
  source: string;
  meta?: Record<string, unknown>;
}

export interface Finding {
  source: string;
  title: string;
  detail?: string;
  url?: string;
  severity?: Severity;
  /** filename of the uploaded image this finding pertains to (when applicable) */
  image?: string;
  /** new entities discovered by this finding (fed back into the engine for pivoting) */
  entities?: Entity[];
  /** arbitrary structured payload for the UI */
  data?: Record<string, unknown>;
}

export interface SourceContext {
  /** API keys / config from env, surfaced to sources */
  keys: Record<string, string | undefined>;
  /** raw uploaded image buffers keyed by entity value (filename) */
  images?: Record<string, Buffer>;
  /** abort signal honoured by fetch calls */
  signal?: AbortSignal;
}

export interface Source {
  id: string;
  label: string;
  /** entity types this source can act on */
  handles: EntityType[];
  /** true if it needs an API key that is currently missing -> engine emits a "configure" note */
  requiresKey?: string;
  run(entity: Entity, ctx: SourceContext): Promise<Finding[]>;
}

/** normalized bounding box on an image: fractions 0..1, (x,y)=top-left corner */
export interface Box {
  x: number;
  y: number;
  w: number;
  h: number;
}

/** precision class of a geo point — drives map marker style + accuracy ring */
export type GeoKind = "gps" | "estimate" | "geocoded";

export interface GeoPoint {
  lat: number;
  lon: number;
  label: string;
  source: string;
  confidence: number;
  /** precision class */
  kind?: GeoKind;
  /** approximate accuracy radius in km (larger = coarser) */
  radiusKm?: number;
  /** how many independent sources agree on this location after fusion */
  corroboration?: number;
  /** labels of the sources that agree */
  sources?: string[];
  /** ground elevation above sea level (metres) at this point, from a DEM lookup */
  elevationM?: number;
}

export interface GeolocateResult {
  /** uploaded filenames analyzed this run */
  images: string[];
  geo: GeoPoint[];
  entities: Entity[];
  findings: Finding[];
  /** sources skipped because a key was missing */
  skipped: { source: string; key: string }[];
  errors: { source: string; entity: string; message: string }[];
  startedAt: string;
  finishedAt: string;
  durationMs: number;
}
