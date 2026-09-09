"use client";

import { useState } from "react";
import type { ReactNode } from "react";
import type { Box, Entity, Finding, GeoPoint, GeolocateResult, Severity } from "@/lib/osint/types";
import { MapView } from "./MapView";

// Top fused point — the single best answer. buildGeo already sorts by
// corroboration then confidence, so geo[0] is it. Surfaced as a hero so the
// actual location isn't buried under the map/findings tabs.
function BestFix({ p }: { p: GeoPoint }) {
  const [copied, setCopied] = useState(false);
  const coords = `${p.lat.toFixed(5)}, ${p.lon.toFixed(5)}`;
  const acc = p.radiusKm
    ? p.radiusKm < 1
      ? `±${Math.round(p.radiusKm * 1000)} m`
      : `±${Math.round(p.radiusKm)} km`
    : null;
  const copy = () => {
    navigator.clipboard?.writeText(coords).then(
      () => {
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
      },
      () => {},
    );
  };
  return (
    <div className="mb-8 rounded-md border-2 border-accent/60 bg-accent/5 p-5">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <p className="eyebrow mb-1 text-accent/80">best fix</p>
          <h2 className="font-display text-2xl leading-tight text-foreground md:text-3xl">{p.label}</h2>
          <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-sm text-muted">
            <button
              onClick={copy}
              title="copy coordinates"
              className="font-mono text-foreground transition hover:text-accent"
            >
              {coords} {copied ? "✓" : "⧉"}
            </button>
            <span>{Math.round(p.confidence * 100)}% confidence</span>
            {p.kind && <span className="uppercase tracking-wider">{p.kind}</span>}
            {acc && <span>{acc}</span>}
            {typeof p.elevationM === "number" && <span>⛰ {p.elevationM} m ASL</span>}
            {p.corroboration && p.corroboration > 1 && (
              <span className="text-accent">✓ {p.corroboration} sources agree</span>
            )}
          </div>
          {p.sources && p.sources.length > 0 && (
            <p className="mt-1 text-[11px] uppercase tracking-wider text-muted/70">{p.sources.join(" · ")}</p>
          )}
        </div>
        <div className="flex flex-wrap gap-2">
          <a
            href={`https://www.google.com/maps?q=&layer=c&cbll=${p.lat},${p.lon}&cbp=11,0,0,0,0`}
            target="_blank"
            rel="noreferrer"
            className="chip rounded-sm border border-accent/50 px-3.5 py-2 text-accent transition hover:bg-accent hover:text-black"
          >
            Street View
          </a>
          <a
            href={`https://www.google.com/maps/dir/?api=1&destination=${p.lat},${p.lon}`}
            target="_blank"
            rel="noreferrer"
            className="chip rounded-sm bg-accent px-3.5 py-2 text-black transition hover:brightness-110"
          >
            Directions →
          </a>
        </div>
      </div>
    </div>
  );
}

// severity → amber-weighted markers (high = full signal amber)
const sevMark: Record<Severity, string> = {
  info: "·",
  low: "▸",
  medium: "▴",
  high: "■",
};
const sevColor: Record<Severity, string> = {
  info: "text-muted",
  low: "text-muted",
  medium: "text-foreground",
  high: "text-accent",
};

function Pill({ e }: { e: Entity }) {
  return (
    <span
      title={`${e.source} · ${(e.confidence * 100).toFixed(0)}%`}
      className="inline-flex items-center gap-2 rounded-sm border border-border bg-panel-2 px-3 py-1.5 text-sm transition hover:border-accent/50"
    >
      <span className="text-[10px] uppercase tracking-widest text-accent/70">{e.type}</span>
      <span className="text-foreground">{e.label && e.label !== e.value ? e.label : e.value}</span>
    </span>
  );
}

function Value({ v }: { v: unknown }) {
  if (v == null) return <span className="text-muted/40">—</span>;
  if (typeof v === "string" && /^https?:\/\//.test(v))
    return (
      <a href={v} target="_blank" rel="noreferrer" className="break-all text-accent underline decoration-accent/40 hover:decoration-accent">
        {v}
      </a>
    );
  if (Array.isArray(v))
    return (
      <ul className="space-y-1">
        {v.map((item, i) => (
          <li key={i}>
            <Value v={item} />
          </li>
        ))}
      </ul>
    );
  if (typeof v === "object") {
    const obj = v as Record<string, unknown>;
    if (typeof obj.url === "string" && typeof obj.label === "string")
      return /^https?:\/\//.test(obj.url) ? (
        <a href={obj.url} target="_blank" rel="noreferrer" className="text-accent underline decoration-accent/40 hover:decoration-accent">
          {obj.label}
        </a>
      ) : (
        <span>{obj.label}</span>
      );
    return (
      <div className="space-y-1 border-l border-border pl-3">
        {Object.entries(obj).map(([k, val]) => (
          <div key={k} className="grid grid-cols-[120px_1fr] gap-3">
            <span className="text-muted">{k}</span>
            <Value v={val} />
          </div>
        ))}
      </div>
    );
  }
  return <span className="break-all">{String(v)}</span>;
}

function FindingCard({ f }: { f: Finding }) {
  const sev = f.severity || "info";
  return (
    <div
      className={`rounded-sm border bg-panel p-5 transition hover:bg-panel-2 ${
        sev === "high" ? "border-accent/60" : "border-border"
      }`}
    >
      <div className="flex items-start gap-3">
        <span className={`text-lg leading-none ${sevColor[sev]}`}>{sevMark[sev]}</span>
        <div className="min-w-0 flex-1">
          <div className="mb-1 flex items-baseline justify-between gap-2">
            <span className="text-[10px] uppercase tracking-[0.25em] text-accent/70">{f.source}</span>
            <span className="text-[10px] uppercase tracking-[0.25em] text-muted">{sev}</span>
          </div>
          <h3 className="text-base font-semibold leading-snug">{f.title}</h3>
          {f.detail && <p className="mt-1.5 text-sm leading-relaxed text-muted">{f.detail}</p>}
          {f.url && (
            <a href={f.url} target="_blank" rel="noreferrer" className="mt-2 block break-all text-sm text-accent underline decoration-accent/40 hover:decoration-accent">
              {f.url}
            </a>
          )}
          {f.data && (
            <div className="mt-3 text-sm text-foreground/90">
              <Value v={f.data} />
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

type Tab = "map" | "analysis" | "faces" | "findings" | "entities";

interface FaceRow {
  face: number;
  box?: Box;
  gender?: string;
  age?: string;
  emotion?: string;
  ethnicity?: string;
  features?: string;
  confidence?: string;
}

function FacesPanel({ findings }: { findings: Finding[] }) {
  const faceFindings = findings.filter((f) => f.source === "faces" && Array.isArray(f.data?.faces));
  const rows: FaceRow[] = faceFindings.flatMap((f) => (f.data!.faces as FaceRow[]) ?? []);

  if (!rows.length) {
    return (
      <p className="text-sm text-muted">
        No faces detected (or face analysis needs <code className="text-accent">VISION_API_KEY</code>/
        <code className="text-accent">GROQ_API_KEY</code> set + dev server restarted).
      </p>
    );
  }

  return (
    <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
      {rows.map((r, i) => (
        <div key={i} className="rounded-sm border border-border bg-panel p-4">
          <div className="mb-2 flex items-baseline justify-between">
            <span className="font-display text-2xl text-accent">FACE {r.face ?? i + 1}</span>
            {r.confidence && <span className="text-[11px] text-muted">{r.confidence}</span>}
          </div>
          <dl className="space-y-1 text-sm">
            {[
              ["gender", r.gender],
              ["age", r.age],
              ["emotion", r.emotion],
              ["ethnicity", r.ethnicity],
              ["features", r.features],
            ]
              .filter(([, v]) => v)
              .map(([k, v]) => (
                <div key={k} className="grid grid-cols-[90px_1fr] gap-2">
                  <dt className="text-muted">{k}</dt>
                  <dd className="text-foreground">{v}</dd>
                </div>
              ))}
          </dl>
        </div>
      ))}
      <p className="col-span-full text-[11px] text-muted">
        AI estimates from pixels — perceived attributes only, often wrong. Not identity, not fact.
      </p>
    </div>
  );
}

// ── Deep analysis view ──────────────────────────────────────────────────────
// The image beside the reasoning that placed it: visual cues, scene "meta",
// pinpoint refinement and camera metadata — the WHY behind each fix, per image.

interface Region {
  label: string;
  kind?: string;
  box: Box;
  note?: string;
}
interface GeoVisionData {
  estimate?: string;
  coords?: string;
  subjectNote?: string;
  cameraPosition?: string;
  viewpoint?: string;
  cameraHeightM?: number;
  confidence?: number;
  reasoning?: string;
  clues?: string[];
  visibleText?: string[];
  landmarks?: string[];
  regions?: Region[];
  alternatives?: string[];
  model?: string;
}
interface SceneData {
  country?: string;
  region?: string;
  drivingSide?: string;
  biome?: string;
  architecture?: string;
  signals?: string[];
  model?: string;
}
interface RefineData {
  exactPlace?: string;
  address?: string;
  crossStreets?: string;
  coords?: string;
  precisionM?: number;
  reasoning?: string;
  model?: string;
}
interface ExifData {
  gps?: { lat: number; lon: number; map: string };
  cameraBearing?: string;
  altitude?: string;
  place?: string;
  camera?: string;
  software?: string;
  taken?: string;
  dimensions?: string;
}

function ConfBar({ value }: { value: number }) {
  const pct = Math.round(Math.max(0, Math.min(1, value)) * 100);
  return (
    <div className="flex items-center gap-3">
      <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-panel-2">
        <div className="h-full rounded-full bg-accent transition-[width] duration-700" style={{ width: `${pct}%` }} />
      </div>
      <span className="w-9 shrink-0 text-right text-xs tabular-nums text-muted">{pct}%</span>
    </div>
  );
}

function Chips({ items, label, accent }: { items?: string[]; label: string; accent?: boolean }) {
  const clean = (items ?? []).map((s) => String(s).trim()).filter(Boolean);
  if (!clean.length) return null;
  return (
    <div>
      <p className="eyebrow mb-1.5">{label}</p>
      <div className="flex flex-wrap gap-1.5">
        {clean.map((s, i) => (
          <span
            key={i}
            className={`rounded-sm border px-2 py-1 text-[12px] leading-tight ${
              accent ? "border-accent/30 bg-accent-soft text-accent" : "border-border bg-panel-2 text-foreground/85"
            }`}
          >
            {s}
          </span>
        ))}
      </div>
    </div>
  );
}

function Field({ k, v }: { k: string; v?: ReactNode }) {
  if (v == null || v === "") return null;
  return (
    <div className="grid grid-cols-[120px_1fr] gap-3">
      <span className="text-muted">{k}</span>
      <span className="break-words text-foreground/90">{v}</span>
    </div>
  );
}

function Module({
  index,
  eyebrow,
  title,
  conf,
  model,
  children,
}: {
  index: string;
  eyebrow: string;
  title?: string;
  conf?: number;
  model?: string;
  children: ReactNode;
}) {
  return (
    <section className="rounded-md border border-border bg-panel p-5 transition hover:border-border-strong">
      <div className="mb-3 flex items-baseline gap-3">
        <span className="font-display text-xl leading-none text-muted/50">{index}</span>
        <span className="eyebrow">{eyebrow}</span>
      </div>
      {title && <h4 className="mb-3 font-display text-2xl leading-tight text-foreground">{title}</h4>}
      {typeof conf === "number" && (
        <div className="mb-4">
          <ConfBar value={conf} />
        </div>
      )}
      <div className="space-y-4 text-sm leading-relaxed text-foreground/90">{children}</div>
      {model && <p className="mt-4 text-[10px] uppercase tracking-wider text-muted/60">via {model}</p>}
    </section>
  );
}

// One boxable thing detected on the image: a face or a geovision feature.
interface Detection {
  id: string;
  group: "face" | "feature";
  tag: string; // short badge shown on the box + in the list
  label: string;
  sub?: string;
  note?: string;
  box: Box;
}

// Box colours: faces cool cyan (distinct from the amber location signal), the
// geolocation evidence amber.
const BOX_COLOR: Record<Detection["group"], string> = {
  face: "#34d3c0",
  feature: "#ffb000",
};
const KIND_TAG: Record<string, string> = {
  building: "BLD",
  landmark: "LMK",
  sign: "TXT",
  vehicle: "VEH",
  terrain: "TER",
  object: "OBJ",
};

function ImageAnalysis({ name, src, findings }: { name: string; src?: string; findings: Finding[] }) {
  const [hovered, setHovered] = useState<string | null>(null);
  const gv = findings.find((f) => f.source === "geovision" && f.data)?.data as GeoVisionData | undefined;
  const sc = findings.find((f) => f.source === "scene" && f.data)?.data as SceneData | undefined;
  const rf = findings.find((f) => f.source === "refine" && f.data)?.data as RefineData | undefined;
  const ex = findings.find((f) => f.source === "exif" && f.data)?.data as ExifData | undefined;
  const faceRows = (findings.find((f) => f.source === "faces" && Array.isArray(f.data?.faces))?.data
    ?.faces ?? []) as FaceRow[];
  const hosted = findings.find((f) => f.source === "reverse-image")?.data?.hostedImage as string | undefined;
  const imgSrc = src || hosted;

  const verdictPlace = rf?.exactPlace || rf?.address || gv?.estimate || ex?.place;
  const verdictCoords =
    rf?.coords || gv?.coords || (ex?.gps ? `${ex.gps.lat}, ${ex.gps.lon}` : undefined);

  // Build overlay detections: geovision evidence boxes + face boxes.
  const dets: Detection[] = [];
  (gv?.regions ?? []).forEach((r, i) => {
    if (!r?.box) return;
    dets.push({
      id: `feat-${i}`,
      group: "feature",
      tag: KIND_TAG[r.kind ?? "object"] ?? "OBJ",
      label: r.label,
      sub: r.kind,
      note: r.note,
      box: r.box,
    });
  });
  faceRows.forEach((fr, i) => {
    if (!fr?.box) return;
    dets.push({
      id: `face-${i}`,
      group: "face",
      tag: `#${fr.face ?? i + 1}`,
      label: `Face ${fr.face ?? i + 1}`,
      sub: [fr.gender, fr.age, fr.emotion].filter((s) => s && s !== "?" && s !== "uncertain").join(" · "),
      note: fr.features,
      box: fr.box,
    });
  });

  // assemble only the modules we actually have data for, numbered in cascade order
  const modules: ReactNode[] = [];
  const idx = () => String(modules.length + 1).padStart(2, "0");

  if (ex && (ex.gps || ex.cameraBearing || ex.camera || ex.taken)) {
    modules.push(
      <Module key="exif" index={idx()} eyebrow="Embedded metadata · EXIF">
        <div className="space-y-1.5">
          <Field
            k="GPS"
            v={
              ex.gps ? (
                <a href={ex.gps.map} target="_blank" rel="noreferrer" className="text-accent underline decoration-accent/40">
                  {ex.gps.lat}, {ex.gps.lon}
                </a>
              ) : (
                <span className="text-muted/60">none — stripped or never written</span>
              )
            }
          />
          <Field k="Camera facing" v={ex.cameraBearing} />
          <Field k="Altitude" v={ex.altitude} />
          <Field k="Place tag" v={ex.place} />
          <Field k="Device" v={ex.camera} />
          <Field k="Software" v={ex.software} />
          <Field k="Taken" v={ex.taken} />
          <Field k="Dimensions" v={ex.dimensions} />
        </div>
      </Module>,
    );
  }

  if (sc && (sc.region || sc.country || sc.signals?.length)) {
    modules.push(
      <Module key="scene" index={idx()} eyebrow="Scene & region — background 'meta'" title={[sc.region, sc.country].filter(Boolean).join(", ") || undefined} model={sc.model}>
        <div className="space-y-1.5">
          <Field k="Drives on" v={sc.drivingSide && sc.drivingSide !== "unknown" ? sc.drivingSide : undefined} />
          <Field k="Biome" v={sc.biome} />
          <Field k="Architecture" v={sc.architecture} />
        </div>
        <Chips label="Region signals" items={sc.signals} />
      </Module>,
    );
  }

  if (gv && (gv.reasoning || gv.clues?.length || gv.estimate)) {
    modules.push(
      <Module key="gv" index={idx()} eyebrow="Visual estimate — pixel content" title={gv.estimate} conf={gv.confidence} model={gv.model}>
        {gv.reasoning && <p>{gv.reasoning}</p>}
        <Chips label="Strongest cues" items={gv.clues} accent />
        <div className="space-y-1.5">
          <Field k="Coordinates" v={gv.coords} />
          <Field k="Viewpoint" v={gv.viewpoint} />
          <Field k="Camera position" v={gv.cameraPosition} />
          <Field k="Lens height" v={typeof gv.cameraHeightM === "number" ? `${gv.cameraHeightM} m` : undefined} />
          {gv.subjectNote && <Field k="Note" v={gv.subjectNote} />}
        </div>
        <Chips label="Named landmarks" items={gv.landmarks} />
        <Chips label="Readable text" items={gv.visibleText} />
        <Chips label="Other candidates" items={gv.alternatives} />
      </Module>,
    );
  }

  if (rf && (rf.exactPlace || rf.address || rf.reasoning)) {
    modules.push(
      <Module key="refine" index={idx()} eyebrow="Pinpoint refinement — second pass" title={rf.exactPlace || rf.address} model={rf.model}>
        {rf.reasoning && <p>{rf.reasoning}</p>}
        <div className="space-y-1.5">
          <Field k="Address" v={rf.address} />
          <Field k="Cross-streets" v={rf.crossStreets} />
          <Field k="Coordinates" v={rf.coords} />
          <Field k="Precision" v={typeof rf.precisionM === "number" ? `±${rf.precisionM} m` : undefined} />
        </div>
      </Module>,
    );
  }

  if (dets.length) {
    modules.push(
      <Module key="dets" index={idx()} eyebrow="On-image detections — boxed evidence">
        <div className="space-y-1.5">
          {dets.map((d) => {
            const on = hovered === d.id;
            return (
              <div
                key={d.id}
                onMouseEnter={() => setHovered(d.id)}
                onMouseLeave={() => setHovered(null)}
                className={`flex cursor-default items-start gap-3 rounded-sm border px-3 py-2 transition ${
                  on ? "border-border-strong bg-panel-2" : "border-transparent"
                }`}
              >
                <span
                  className="mt-0.5 shrink-0 rounded-[3px] px-1.5 py-0.5 text-[10px] font-semibold text-black"
                  style={{ background: BOX_COLOR[d.group] }}
                >
                  {d.tag}
                </span>
                <div className="min-w-0">
                  <p className="text-foreground">
                    {d.label}
                    {d.sub && <span className="text-muted"> · {d.sub}</span>}
                  </p>
                  {d.note && <p className="text-[13px] leading-snug text-muted">{d.note}</p>}
                </div>
              </div>
            );
          })}
        </div>
      </Module>,
    );
  }

  return (
    <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.35fr)]">
      <div className="lg:sticky lg:top-6 lg:self-start">
        <div className="reticle flex justify-center overflow-hidden rounded-md border border-border bg-panel-2">
          {imgSrc ? (
            <div className="relative inline-block leading-none">
              {/* eslint-disable-next-line @next/next/no-img-element */}
              <img src={imgSrc} alt={name} className="block max-h-[72vh] w-auto select-none" />
              {/* box overlay — container is the image, so fractional coords map 1:1 */}
              <div className="absolute inset-0">
                {dets.map((d) => {
                  const on = hovered === d.id;
                  const color = BOX_COLOR[d.group];
                  return (
                    <div
                      key={d.id}
                      onMouseEnter={() => setHovered(d.id)}
                      onMouseLeave={() => setHovered(null)}
                      className="absolute transition-all duration-150"
                      style={{
                        left: `${d.box.x * 100}%`,
                        top: `${d.box.y * 100}%`,
                        width: `${d.box.w * 100}%`,
                        height: `${d.box.h * 100}%`,
                        border: `2px solid ${color}`,
                        boxShadow: on ? `0 0 0 2px ${color}, 0 0 18px ${color}99` : "0 0 0 1px #00000080",
                        background: on ? `${color}22` : "transparent",
                        opacity: hovered && !on ? 0.35 : 1,
                      }}
                    >
                      <span
                        className="absolute -top-[1px] left-[-2px] -translate-y-full rounded-t-[3px] px-1.5 py-0.5 text-[10px] font-semibold leading-none text-black"
                        style={{ background: color }}
                      >
                        {d.tag}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          ) : (
            <div className="flex h-64 w-full items-center justify-center text-sm text-muted">image preview unavailable</div>
          )}
        </div>
        <div className="mt-3 flex items-baseline justify-between gap-3">
          <span className="truncate font-mono text-xs text-muted" title={name}>
            {name}
          </span>
          {verdictPlace && (
            <span className="shrink-0 text-xs text-accent">{verdictCoords ? `${verdictCoords}` : ""}</span>
          )}
        </div>
        {verdictPlace && (
          <p className="mt-1 font-display text-xl leading-tight text-foreground">{verdictPlace}</p>
        )}
        {dets.length > 0 && (
          <p className="mt-2 text-[11px] text-muted/70">
            {dets.length} detection{dets.length > 1 ? "s" : ""} boxed — hover to inspect. AI-placed, approximate.
          </p>
        )}
      </div>
      <div className="space-y-4">
        {modules.length ? (
          modules
        ) : (
          <p className="rounded-md border border-dashed border-border bg-panel p-6 text-sm text-muted">
            No analysis modules for this image. The AI sources need{" "}
            <code className="text-accent">VISION_API_KEY</code> (or{" "}
            <code className="text-accent">GROQ_API_KEY</code>); without a key only EXIF metadata is read.
          </p>
        )}
      </div>
    </div>
  );
}

function AnalysisView({ result, images }: { result: GeolocateResult; images?: Record<string, string> }) {
  const names = result.images ?? [];
  if (!names.length) return <p className="text-sm text-muted">No images to analyze.</p>;
  return (
    <div className="space-y-12">
      {names.map((name) => (
        <ImageAnalysis
          key={name}
          name={name}
          src={images?.[name]}
          findings={result.findings.filter((f) => f.image === name)}
        />
      ))}
    </div>
  );
}

function Stat({ n, label, accent }: { n: number | string; label: string; accent?: boolean }) {
  return (
    <div className="flex flex-col">
      <span className={`font-display text-3xl leading-none ${accent ? "text-accent" : "text-foreground"}`}>{n}</span>
      <span className="eyebrow mt-1">{label}</span>
    </div>
  );
}

export function Results({
  result,
  images,
}: {
  result: GeolocateResult;
  images?: Record<string, string>;
}) {
  const [tab, setTab] = useState<Tab>("map");
  const high = result.findings.filter((f) => f.severity === "high").length;
  const geo = result.geo ?? [];
  const faceCount = result.findings
    .filter((f) => f.source === "faces" && Array.isArray(f.data?.faces))
    .reduce((n, f) => n + (f.data!.faces as unknown[]).length, 0);
  const tabs: Tab[] = ["map", "analysis", "faces", "findings", "entities"];

  return (
    <div className="mt-10 rise">
      <div className="mb-8 flex flex-wrap items-end gap-x-10 gap-y-4 border-b border-border pb-6">
        <Stat n={geo.length} label="map points" accent />
        <Stat n={result.entities.length} label="entities" />
        <Stat n={result.findings.length} label="findings" />
        {high > 0 && <Stat n={high} label="high signal" accent />}
        <Stat n={`${result.durationMs}ms`} label="elapsed" />
        {result.skipped.length > 0 && <Stat n={result.skipped.length} label="skipped" />}
      </div>

      {geo.length > 0 && <BestFix p={geo[0]} />}

      {result.skipped.length > 0 && (
        <div className="mb-6 rounded-sm border border-border bg-panel-2 px-4 py-3 text-sm text-muted">
          configure to enable: {result.skipped.map((s) => `${s.source} (${s.key})`).join(" · ")}
        </div>
      )}

      <div className="mb-6 flex gap-2 border-b border-border">
        {tabs.map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`-mb-px border-b-2 px-5 py-2.5 text-sm uppercase tracking-widest transition ${
              tab === t
                ? "border-accent text-foreground"
                : "border-transparent text-muted hover:text-foreground"
            }`}
          >
            {t}
            {t === "map" && geo.length > 0 ? ` (${geo.length})` : ""}
            {t === "analysis" && result.images.length > 0 ? ` (${result.images.length})` : ""}
            {t === "faces" && faceCount > 0 ? ` (${faceCount})` : ""}
          </button>
        ))}
      </div>

      {tab === "map" && <MapView points={geo} />}

      {tab === "analysis" && <AnalysisView result={result} images={images} />}

      {tab === "faces" && <FacesPanel findings={result.findings} />}

      {tab === "entities" && (
        <div className="flex flex-wrap gap-2">
          {result.entities.map((e) => (
            <Pill key={e.id + e.source} e={e} />
          ))}
        </div>
      )}

      {tab === "findings" && (
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {result.findings.map((f, i) => (
            <FindingCard key={i} f={f} />
          ))}
        </div>
      )}

      {result.errors.length > 0 && (
        <details className="mt-8 text-xs text-muted">
          <summary className="cursor-pointer uppercase tracking-widest hover:text-foreground">
            {result.errors.length} source errors
          </summary>
          <ul className="mt-3 space-y-1">
            {result.errors.map((e, i) => (
              <li key={i}>
                {e.source} / {e.entity}: {e.message}
              </li>
            ))}
          </ul>
        </details>
      )}
    </div>
  );
}
