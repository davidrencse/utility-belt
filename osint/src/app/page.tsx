"use client";

import { useState, useMemo, useEffect } from "react";
import type { GeolocateResult } from "@/lib/osint/types";
import { Results } from "@/components/Results";

export default function Home() {
  const [files, setFiles] = useState<File[]>([]);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<GeolocateResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);
  // Gate the submit button's disabled state on mount so SSR HTML and the first
  // client render agree (both: enabled). Avoids the hydration mismatch a form-
  // filler extension can otherwise trigger by touching the button pre-hydration.
  const [mounted, setMounted] = useState(false);
  // eslint-disable-next-line react-hooks/set-state-in-effect
  useEffect(() => setMounted(true), []);

  // Mint one object URL per file (not on every render) and revoke them when the
  // file set changes or the component unmounts — otherwise each render leaks a
  // fresh blob URL per thumbnail and forces the image to re-decode.
  const previews = useMemo(() => files.map((f) => URL.createObjectURL(f)), [files]);
  useEffect(() => () => previews.forEach((u) => URL.revokeObjectURL(u)), [previews]);

  // Clipboard paste anywhere on the page. A React onPaste on the form only fires
  // when a focusable child has focus — the upload UI has none — so listen on the
  // window instead.
  useEffect(() => {
    function onPaste(e: ClipboardEvent) {
      const items = e.clipboardData?.items;
      if (!items) return;
      const imgs: File[] = [];
      for (const it of Array.from(items)) {
        if (it.kind === "file" && it.type.startsWith("image/")) {
          const f = it.getAsFile();
          if (f) imgs.push(f);
        }
      }
      if (imgs.length) {
        e.preventDefault();
        addFiles(imgs);
      }
    }
    // Drag/drop anywhere on the page. Must preventDefault on dragover or the
    // browser just opens the dropped image as a navigation. depth tracks nested
    // dragenter/leave so the overlay doesn't flicker over child elements.
    let depth = 0;
    function onDragEnter(e: DragEvent) {
      if (!e.dataTransfer?.types.includes("Files")) return;
      e.preventDefault();
      depth++;
      setDragging(true);
    }
    function onDragOver(e: DragEvent) {
      if (e.dataTransfer?.types.includes("Files")) e.preventDefault();
    }
    function onDragLeave(e: DragEvent) {
      if (!e.dataTransfer?.types.includes("Files")) return;
      depth = Math.max(0, depth - 1);
      if (depth === 0) setDragging(false);
    }
    function onDrop(e: DragEvent) {
      if (!e.dataTransfer) return;
      e.preventDefault();
      depth = 0;
      setDragging(false);
      addFiles(e.dataTransfer.files);
    }

    window.addEventListener("paste", onPaste);
    window.addEventListener("dragenter", onDragEnter);
    window.addEventListener("dragover", onDragOver);
    window.addEventListener("dragleave", onDragLeave);
    window.addEventListener("drop", onDrop);
    return () => {
      window.removeEventListener("paste", onPaste);
      window.removeEventListener("dragenter", onDragEnter);
      window.removeEventListener("dragover", onDragOver);
      window.removeEventListener("dragleave", onDragLeave);
      window.removeEventListener("drop", onDrop);
    };
  }, []);

  function addFiles(list: FileList | File[] | null | undefined) {
    if (!list) return;
    const imgs = Array.from(list).filter((f) => f.type.startsWith("image/"));
    if (!imgs.length) return;
    setFiles((prev) => {
      const seen = new Set(prev.map((f) => f.name + ":" + f.size));
      return [...prev, ...imgs.filter((f) => !seen.has(f.name + ":" + f.size))];
    });
  }

  function removeFile(i: number) {
    setFiles((prev) => prev.filter((_, idx) => idx !== i));
  }

  async function run() {
    if (!files.length) return;
    setLoading(true);
    setError(null);
    setResult(null);
    // Warm the map bundle during the (multi-second) analysis wait: maplibre-gl is
    // a large dynamic chunk MapView only imports once results render. Kicking the
    // module fetch+parse off now (fire-and-forget, module-cached) means the map
    // paints near-instantly instead of starting a cold import after the response.
    void import("maplibre-gl");
    try {
      const fd = new FormData();
      for (const f of files) fd.append("images", f, f.name);
      const res = await fetch("/api/geolocate", { method: "POST", body: fd });
      const json = await res.json();
      if (!res.ok) throw new Error(json.error || "Request failed");
      setResult(json as GeolocateResult);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed");
    } finally {
      setLoading(false);
    }
  }

  const canRun = files.length > 0 && !loading;

  return (
    <main className="mx-auto w-full max-w-[1700px] px-6 py-10 md:px-12 md:py-14">
      <header className="mb-12 border-b border-border pb-9">
        <div className="mb-5 flex items-center justify-between">
          <p className="eyebrow">Forensic Image Geolocation</p>
          <p className="eyebrow hidden sm:block">No keys required · Runs free</p>
        </div>
        <div className="flex flex-col gap-7 md:flex-row md:items-end md:justify-between">
          <h1 className="font-display text-6xl leading-[0.9] tracking-tight text-foreground md:text-8xl">
            Geo<span className="font-display-italic accent-text">locator</span>
          </h1>
          <p className="max-w-sm text-[0.95rem] leading-relaxed text-muted md:text-right">
            Find where a photo was taken. It reads embedded GPS, estimates the
            place from pixel content with AI, reverse-searches the web, and fuses
            every signal onto a single map.
          </p>
        </div>
      </header>

      {dragging && (
        <div className="pointer-events-none fixed inset-0 z-50 flex items-center justify-center bg-black/85 backdrop-blur-sm">
          <span className="font-display text-5xl italic text-accent md:text-7xl">
            Drop to add
          </span>
        </div>
      )}

      <form
        className={`relative overflow-hidden rounded-lg border bg-panel transition ${
          dragging ? "border-accent shadow-[0_0_0_1px_var(--accent)]" : "border-border"
        }`}
        onSubmit={(e) => {
          e.preventDefault();
          run();
        }}
      >
        {files.length === 0 ? (
          <label className="group flex min-h-[320px] cursor-pointer flex-col items-center justify-center gap-4 p-12 text-center transition hover:bg-panel-2">
            <span className="font-display text-4xl text-foreground md:text-6xl">
              Drop a photo to <span className="font-display-italic accent-text">locate</span> it
            </span>
            <span className="max-w-md text-[0.95rem] leading-relaxed text-muted">
              Drag in, paste, or choose one or more images. Everything runs free —
              the AI pixel estimate just needs an optional vision API key.
            </span>
            <span className="chip mt-2 inline-flex items-center gap-2 rounded-sm border border-accent/40 bg-accent-soft px-5 py-2.5 text-accent transition group-hover:bg-accent group-hover:text-black">
              Choose images
            </span>
            <input
              type="file"
              accept="image/*"
              multiple
              className="hidden"
              onChange={(e) => {
                addFiles(e.target.files);
                e.target.value = "";
              }}
            />
          </label>
        ) : (
          <div className="grid grid-cols-2 gap-3 p-5 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6">
            {files.map((f, i) => (
              <span
                key={f.name + i}
                className="group relative overflow-hidden rounded-sm border border-border bg-panel-2"
              >
                {/* eslint-disable-next-line @next/next/no-img-element */}
                <img
                  src={previews[i]}
                  alt=""
                  className="h-28 w-full object-cover grayscale transition group-hover:grayscale-0"
                />
                <span className="absolute inset-x-0 bottom-0 truncate bg-gradient-to-t from-black/90 to-transparent px-2 py-1.5 text-[11px] text-foreground/90">
                  {f.name}
                </span>
                <button
                  type="button"
                  onClick={() => removeFile(i)}
                  className="absolute right-1.5 top-1.5 flex h-6 w-6 items-center justify-center rounded-sm bg-black/70 text-sm text-foreground opacity-0 transition hover:bg-accent hover:text-black group-hover:opacity-100"
                  aria-label="remove"
                >
                  ✕
                </button>
              </span>
            ))}
          </div>
        )}

        <div className="flex flex-wrap items-center gap-4 border-t border-border bg-panel-2/40 px-5 py-4">
          <label className="chip cursor-pointer text-muted transition hover:text-accent">
            + Add more
            <input
              type="file"
              accept="image/*"
              multiple
              className="hidden"
              onChange={(e) => {
                addFiles(e.target.files);
                e.target.value = "";
              }}
            />
          </label>
          <span className="ml-auto text-sm text-muted">
            {files.length
              ? `${files.length} image${files.length > 1 ? "s" : ""} ready`
              : "No images yet"}
          </span>
          <button
            type="submit"
            suppressHydrationWarning
            disabled={mounted ? !canRun : false}
            className="chip group relative overflow-hidden rounded-sm bg-accent px-9 py-3.5 text-sm font-semibold text-black transition hover:brightness-110 disabled:cursor-not-allowed disabled:bg-border disabled:text-muted"
          >
            <span className="relative z-10">{loading ? "Locating…" : "Locate"}</span>
            {!loading && canRun && (
              <span className="pointer-events-none absolute inset-y-0 -left-full w-1/3 skew-x-12 bg-white/30 [animation:sheen_2.6s_ease-in-out_infinite]" />
            )}
          </button>
        </div>
      </form>

      {error && (
        <div className="mt-6 flex items-center gap-3 rounded-md border-2 border-accent/50 bg-accent/10 px-5 py-4 text-sm text-foreground">
          <span className="font-display text-lg text-accent">!</span> {error}
        </div>
      )}

      {result && (
        <Results
          result={result}
          images={Object.fromEntries(files.map((f, i) => [f.name, previews[i]]))}
        />
      )}
    </main>
  );
}
