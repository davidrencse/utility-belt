"use client";

import { useEffect, useRef, useState } from "react";
import "maplibre-gl/dist/maplibre-gl.css";
import type { StyleSpecification } from "maplibre-gl";
import type { GeoPoint } from "@/lib/osint/types";

// ── Basemap modes ──────────────────────────────────────────────────────────
// recon     : custom dark monochrome vector + 3D buildings (forced B/W via CSS)
// streets   : full-colour realistic OSM vector (OpenFreeMap Liberty)
// satellite : real aerial imagery (Esri) + elevation relief + OSM 3D buildings
// ALL FREE, NO API KEY.
export type MapMode = "recon" | "streets" | "satellite";

const STREETS_STYLE_URL = "https://tiles.openfreemap.org/styles/liberty";

// Satellite mode — free "game map" 3D:
//   - Esri World Imagery as the ground (real aerial photography).
//   - AWS terrarium DEM terrain (free, no key) for accurate relief when tilted.
//   - OpenMapTiles vector buildings extruded by real OSM heights, vertical-
//     gradient shaded so they read as 3D massing, not flat grey blocks.
//   - imagery maxzoom 19: MapLibre OVERZOOMS past z19 instead of blanking.
const SATELLITE_STYLE = {
  version: 8 as const,
  glyphs: "https://tiles.openfreemap.org/fonts/{fontstack}/{range}.pbf",
  sources: {
    "esri-imagery": {
      type: "raster" as const,
      tiles: [
        "https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}",
      ],
      tileSize: 256,
      maxzoom: 19,
      attribution: "Imagery © Esri · Maxar · Earthstar Geographics",
    },
    "esri-ref": {
      type: "raster" as const,
      tiles: [
        "https://server.arcgisonline.com/ArcGIS/rest/services/Reference/World_Boundaries_and_Places/MapServer/tile/{z}/{y}/{x}",
      ],
      tileSize: 256,
      maxzoom: 19,
    },
    openmaptiles: {
      type: "vector" as const,
      url: "https://tiles.openfreemap.org/planet",
    },
    "terrain-dem": {
      type: "raster-dem" as const,
      tiles: ["https://s3.amazonaws.com/elevation-tiles-prod/terrarium/{z}/{x}/{y}.png"],
      encoding: "terrarium" as const,
      tileSize: 256,
      // maxzoom 14 (not 15): the render sources (esri / openmaptiles vector) cap at
      // z14, so past z14 their tiles overscale. MapLibre warns "cannot calculate
      // elevation if elevation maxzoom > source.maxzoom" when the DEM maxzoom
      // exceeds the overscaled render tile's canonical zoom — matching at 14 silences
      // it with no visible relief loss.
      maxzoom: 14,
      attribution: "Elevation © AWS Terrain Tiles",
    },
  },
  // No static `terrain` here — the 3D mesh is attached on demand (syncTerrain)
  // only while the camera is tilted, so flat views don't pay to build it.
  layers: [
    { id: "sat", type: "raster" as const, source: "esri-imagery" },
    {
      id: "sat-ref",
      type: "raster" as const,
      source: "esri-ref",
      // fade labels out up close so they don't smear across the 3D rooftops
      paint: { "raster-opacity": ["interpolate", ["linear"], ["zoom"], 13, 0.8, 16, 0] },
    },
    {
      id: "building-3d",
      type: "fill-extrusion" as const,
      source: "openmaptiles",
      "source-layer": "building",
      // building geometry exists in the vector tiles from z13 — start extruding at
      // 13 (not 14) so 3D buildings appear a full zoom level earlier as you zoom in.
      minzoom: 13,
      paint: {
        "fill-extrusion-color": [
          "interpolate",
          ["linear"],
          ["get", "render_height"],
          0,
          "#d8dde2",
          40,
          "#b9c0c7",
          120,
          "#959da6",
          300,
          "#79828c",
        ],
        "fill-extrusion-height": ["get", "render_height"],
        "fill-extrusion-base": ["get", "render_min_height"],
        "fill-extrusion-opacity": 0.9,
        "fill-extrusion-vertical-gradient": true,
      },
    },
  ],
};

function styleFor(mode: MapMode): StyleSpecification | string {
  if (mode === "streets") return STREETS_STYLE_URL;
  if (mode === "satellite") return SATELLITE_STYLE as unknown as StyleSpecification;
  return STYLE as unknown as StyleSpecification;
}

// Free, no-key vector basemap (OpenFreeMap). Custom dark monochrome style with
// 3D building extrusion (Google-Earth style). Forced to pure B/W via CSS filter.
const STYLE = {
  version: 8 as const,
  // glyph endpoint — required for any text/symbol (label) layer
  glyphs: "https://tiles.openfreemap.org/fonts/{fontstack}/{range}.pbf",
  sources: {
    openmaptiles: {
      type: "vector" as const,
      url: "https://tiles.openfreemap.org/planet",
      attribution: "© OpenStreetMap · OpenFreeMap",
    },
    // Same free, no-key AWS terrarium DEM the satellite mode uses, so the dark
    // recon basemap gains real ground relief when tilted/globe-spun.
    // TWO separate DEM sources on purpose: MapLibre warns if one raster-dem source
    // backs both a hillshade layer and the 3D terrain mesh ("use two separate
    // sources to improve rendering quality"). `hillshade-dem` feeds the 2D relief
    // layer; `terrain-dem` feeds setTerrain (syncTerrain). Same tiles, HTTP-cached.
    "hillshade-dem": {
      type: "raster-dem" as const,
      tiles: ["https://s3.amazonaws.com/elevation-tiles-prod/terrarium/{z}/{x}/{y}.png"],
      encoding: "terrarium" as const,
      tileSize: 256,
      maxzoom: 14,
      attribution: "Elevation © AWS Terrain Tiles",
    },
    "terrain-dem": {
      type: "raster-dem" as const,
      tiles: ["https://s3.amazonaws.com/elevation-tiles-prod/terrarium/{z}/{x}/{y}.png"],
      encoding: "terrarium" as const,
      tileSize: 256,
      maxzoom: 14, // match render-source maxzoom (see satellite terrain-dem note)
    },
  },
  // Terrain mesh attached on demand (syncTerrain) only when tilted; the hillshade
  // layer below renders flat relief off the separate `hillshade-dem` source.
  layers: [
    { id: "bg", type: "background" as const, paint: { "background-color": "#1a1a1a" } },
    // Relief shading from the DEM — makes elevation visible on the flat dark map
    // (mountains/valleys read as light/shadow) even top-down, not only when tilted.
    {
      id: "hillshade",
      type: "hillshade" as const,
      source: "hillshade-dem",
      paint: {
        "hillshade-shadow-color": "#000000",
        "hillshade-highlight-color": "#5c5c5c",
        "hillshade-accent-color": "#000000",
        "hillshade-exaggeration": 0.55,
      },
    },
    {
      id: "water",
      type: "fill" as const,
      source: "openmaptiles",
      "source-layer": "water",
      paint: { "fill-color": "#0d0d0d" },
    },
    {
      id: "roads",
      type: "line" as const,
      source: "openmaptiles",
      "source-layer": "transportation",
      minzoom: 7,
      paint: {
        "line-color": "#3a3a3a",
        "line-width": ["interpolate", ["linear"], ["zoom"], 7, 0.4, 16, 2.4],
      },
    },
    {
      id: "building-3d",
      type: "fill-extrusion" as const,
      source: "openmaptiles",
      "source-layer": "building",
      // building geometry exists in the vector tiles from z13 — start extruding at
      // 13 (not 14) so 3D buildings appear a full zoom level earlier as you zoom in.
      minzoom: 13,
      paint: {
        "fill-extrusion-color": [
          "interpolate",
          ["linear"],
          ["get", "render_height"],
          0,
          "#4a4a4a",
          40,
          "#666666",
          120,
          "#888888",
          300,
          "#aaaaaa",
        ],
        "fill-extrusion-height": ["get", "render_height"],
        "fill-extrusion-base": ["get", "render_min_height"],
        "fill-extrusion-opacity": 0.92,
      },
    },

    // ── Place labels (Google-Maps-style zoom staging) ────────────────────────
    // Vector "place" layer carries country/state/city/town/village/suburb/…
    // points. We split them into layers, each fading in at the zoom where it
    // makes sense, sized by importance, with collision so they don't overlap.

    // Streets: line-following labels, only once you're zoomed into a city.
    {
      id: "label-street",
      type: "symbol" as const,
      source: "openmaptiles",
      "source-layer": "transportation_name",
      minzoom: 13,
      layout: {
        "symbol-placement": "line" as const,
        "text-field": ["coalesce", ["get", "name:en"], ["get", "name"]] as unknown as string,
        "text-font": ["Noto Sans Regular"],
        "text-size": ["interpolate", ["linear"], ["zoom"], 13, 9, 18, 13],
        "text-max-angle": 30,
        "symbol-spacing": 250,
      },
      paint: {
        "text-color": "#cbcbcb",
        "text-halo-color": "#000000",
        "text-halo-width": 1.2,
      },
    },

    // Neighbourhoods / suburbs / villages — finest place tier.
    {
      id: "label-place-minor",
      type: "symbol" as const,
      source: "openmaptiles",
      "source-layer": "place",
      filter: [
        "match",
        ["get", "class"],
        ["suburb", "neighbourhood", "quarter", "hamlet", "village", "island"],
        true,
        false,
      ] as unknown as boolean,
      minzoom: 11,
      layout: {
        "text-field": ["coalesce", ["get", "name:en"], ["get", "name"]] as unknown as string,
        "text-font": ["Noto Sans Regular"],
        "text-size": ["interpolate", ["linear"], ["zoom"], 11, 10, 16, 15],
        "text-max-width": 8,
        "symbol-sort-key": ["coalesce", ["get", "rank"], 20] as unknown as number,
      },
      paint: {
        "text-color": "#bdbdbd",
        "text-halo-color": "#000000",
        "text-halo-width": 1.2,
      },
    },

    // Cities & towns — visible across most mid zooms; important ones (low rank)
    // appear earlier, are bigger, and win label collisions.
    {
      id: "label-place-city",
      type: "symbol" as const,
      source: "openmaptiles",
      "source-layer": "place",
      filter: ["match", ["get", "class"], ["city", "town"], true, false] as unknown as boolean,
      minzoom: 3,
      maxzoom: 15,
      layout: {
        "text-field": ["coalesce", ["get", "name:en"], ["get", "name"]] as unknown as string,
        "text-font": ["Noto Sans Regular"],
        "text-size": [
          "interpolate",
          ["linear"],
          ["zoom"],
          3,
          ["case", ["<=", ["coalesce", ["get", "rank"], 10], 2], 12, 0],
          7,
          ["case", ["<=", ["coalesce", ["get", "rank"], 10], 6], 14, 11],
          12,
          ["case", ["<=", ["coalesce", ["get", "rank"], 10], 6], 19, 15],
        ] as unknown as number,
        "text-max-width": 8,
        "symbol-sort-key": ["coalesce", ["get", "rank"], 10] as unknown as number,
      },
      paint: {
        "text-color": "#ededed",
        "text-halo-color": "#000000",
        "text-halo-width": 1.3,
      },
    },

    // States / provinces — mid zoom, uppercased + spaced, fade out as cities take over.
    {
      id: "label-state",
      type: "symbol" as const,
      source: "openmaptiles",
      "source-layer": "place",
      filter: ["==", ["get", "class"], "state"] as unknown as boolean,
      minzoom: 3,
      maxzoom: 9,
      layout: {
        "text-field": ["coalesce", ["get", "name:en"], ["get", "name"]] as unknown as string,
        "text-font": ["Noto Sans Regular"],
        "text-transform": "uppercase" as const,
        "text-letter-spacing": 0.1,
        "text-size": ["interpolate", ["linear"], ["zoom"], 3, 10, 6, 13, 9, 15],
        "text-max-width": 8,
      },
      paint: {
        "text-color": "#9a9a9a",
        "text-halo-color": "#000000",
        "text-halo-width": 1.2,
        "text-opacity": ["interpolate", ["linear"], ["zoom"], 3, 0, 4, 0.9, 7.5, 0.9, 9, 0],
      },
    },

    // Countries — visible when zoomed out, bold + uppercased, fade as you zoom in.
    {
      id: "label-country",
      type: "symbol" as const,
      source: "openmaptiles",
      "source-layer": "place",
      filter: ["==", ["get", "class"], "country"] as unknown as boolean,
      maxzoom: 9,
      layout: {
        "text-field": ["coalesce", ["get", "name:en"], ["get", "name"]] as unknown as string,
        "text-font": ["Noto Sans Bold"],
        "text-transform": "uppercase" as const,
        "text-letter-spacing": 0.14,
        "text-size": ["interpolate", ["linear"], ["zoom"], 1, 9, 4, 14, 7, 18],
        "text-max-width": 7,
        "symbol-sort-key": ["coalesce", ["get", "rank"], 5] as unknown as number,
      },
      paint: {
        "text-color": "#f4f4f4",
        "text-halo-color": "#000000",
        "text-halo-width": 1.5,
        "text-opacity": ["interpolate", ["linear"], ["zoom"], 1, 0.75, 3, 1, 6.5, 1, 9, 0],
      },
    },

    // Oceans & seas — italic water labels for orientation when zoomed out.
    {
      id: "label-water",
      type: "symbol" as const,
      source: "openmaptiles",
      "source-layer": "water_name",
      layout: {
        "text-field": ["coalesce", ["get", "name:en"], ["get", "name"]] as unknown as string,
        "text-font": ["Noto Sans Italic"],
        "text-size": ["interpolate", ["linear"], ["zoom"], 2, 10, 8, 14],
        "text-max-width": 8,
        "symbol-placement": "point" as const,
      },
      paint: {
        "text-color": "#5f6b78",
        "text-halo-color": "#000000",
        "text-halo-width": 1,
      },
    },
  ],
};

// Escape untrusted strings before they go into Popup.setHTML(). Point labels
// and source names derive from third-party fields (AI landmarks, EXIF/IPTC place
// tags, geocoder display names) and must not be able to inject markup.
function esc(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// Keyless Google Street View deep-link.
// NOTE: the api=1 `map_action=pano&viewpoint=` form does NOT search — it needs a
// panorama essentially AT the exact coord, so estimate points landing on a roof/
// field/water open as a BLACK void. The legacy `layer=c&cbll=` form instead
// performs a nearest-panorama search and snaps to the closest coverage, so it
// degrades to a real street instead of black. cbp sets default heading/zoom.
function streetViewUrl(lat: number, lon: number): string {
  return `https://www.google.com/maps?q=&layer=c&cbll=${lat},${lon}&cbp=11,0,0,0,0`;
}

// approximate geodesic circle as a ring of [lon,lat] coords (for accuracy rings)
function circlePolygon(lon: number, lat: number, km: number, steps = 64): [number, number][] {
  const dLat = km / 110.574;
  const dLon = km / (111.32 * Math.cos((lat * Math.PI) / 180));
  const ring: [number, number][] = [];
  for (let i = 0; i <= steps; i++) {
    const t = (2 * Math.PI * i) / steps;
    ring.push([lon + dLon * Math.cos(t), lat + dLat * Math.sin(t)]);
  }
  return ring;
}

// Accuracy rings — circle polygon per point, sized by its radiusKm. Conveys
// uncertainty: tiny for GPS, huge for coarse estimates. Re-added after every
// setStyle() because changing styles drops all custom sources/layers.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function addAccuracy(map: any, points: GeoPoint[]) {
  if (map.getSource("accuracy")) return;
  map.addSource("accuracy", {
    type: "geojson",
    data: {
      type: "FeatureCollection",
      features: points
        .filter((p) => p.radiusKm && p.radiusKm > 0.1)
        .map((p) => ({
          type: "Feature" as const,
          properties: { conf: p.confidence },
          geometry: {
            type: "Polygon" as const,
            coordinates: [circlePolygon(p.lon, p.lat, p.radiusKm as number)],
          },
        })),
    },
  });
  map.addLayer({
    id: "accuracy-fill",
    type: "fill",
    source: "accuracy",
    paint: { "fill-color": "#ffb000", "fill-opacity": 0.08 },
  });
  map.addLayer({
    id: "accuracy-line",
    type: "line",
    source: "accuracy",
    paint: {
      "line-color": "#ffb000",
      "line-width": 1.2,
      "line-opacity": ["interpolate", ["linear"], ["get", "conf"], 0, 0.3, 1, 0.8],
      "line-dasharray": [2, 2],
    },
  });
}

const TERRAIN_EXAGGERATION = 1.35;

// Build the 3D terrain mesh (the expensive part) ONLY while the camera is
// tilted — a flat top-down view gains nothing from a deformed mesh but still
// pays to compute it. Hillshade relief is a separate 2D layer and keeps working
// flat. Cheap to call on every pitchend / style load; it no-ops when already in
// the right state. Requires the "terrain-dem" source to be present in the style.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function syncTerrain(map: any) {
  if (!map.getSource?.("terrain-dem")) return;
  const want = map.getPitch() > 1;
  const has = !!map.getTerrain?.();
  if (want && !has) map.setTerrain({ source: "terrain-dem", exaggeration: TERRAIN_EXAGGERATION });
  else if (!want && has) map.setTerrain(null);
}

const MODES: { id: MapMode; label: string }[] = [
  { id: "recon", label: "◐ Recon" },
  { id: "streets", label: "▦ Streets" },
  { id: "satellite", label: "⊕ Satellite" },
];

export function MapView({ points }: { points: GeoPoint[] }) {
  const ref = useRef<HTMLDivElement>(null);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const mapRef = useRef<any>(null);
  const [globe, setGlobe] = useState(false); // flat mercator loads faster; globe is opt-in
  const [mode, setMode] = useState<MapMode>("recon");
  // The init effect rebuilds the map whenever `points` change (a new upload),
  // but mode/globe are not in its deps (live toggles use changeMode/toggle, not
  // a rebuild). Mirror them into refs so a rebuild restores the active basemap +
  // projection instead of snapping back to recon/mercator while the UI still
  // reads "satellite"/"globe".
  const [svMode, setSvMode] = useState(false); // click-to-open-StreetView mode
  const modeRef = useRef(mode);
  const globeRef = useRef(globe);
  const svModeRef = useRef(svMode);
  useEffect(() => {
    modeRef.current = mode;
    globeRef.current = globe;
    svModeRef.current = svMode;
  }, [mode, globe, svMode]);

  // crosshair cursor while Street-View pick mode is armed
  useEffect(() => {
    const map = mapRef.current;
    if (!map) return;
    const canvas = map.getCanvas?.();
    if (canvas) canvas.style.cursor = svMode ? "crosshair" : "";
  }, [svMode]);

  // One-time cleanup: the old Google-3D caching service worker no longer exists.
  // Unregister any leftover registration + drop its tile cache so a stale worker
  // doesn't keep intercepting requests.
  useEffect(() => {
    if (typeof navigator === "undefined" || !("serviceWorker" in navigator)) return;
    navigator.serviceWorker.getRegistrations?.().then((rs) => rs.forEach((r) => r.unregister()));
    if (typeof caches !== "undefined") {
      caches.keys().then((keys) => keys.filter((k) => k.startsWith("g3d-")).forEach((k) => caches.delete(k)));
    }
  }, []);

  useEffect(() => {
    if (!ref.current || mapRef.current) return;
    let cancelled = false;

    (async () => {
      const maplibregl = (await import("maplibre-gl")).default;
      if (cancelled || !ref.current) return;

      // Zooming into a fresh area needs many tiles at once (vector basemap +
      // building geometry + DEM + imagery). The default cap of 16 in-flight tile
      // requests bottlenecks that burst on HTTP/2 hosts (openfreemap/esri/S3 all
      // multiplex), so the new viewport — and its 3D buildings — fills in slower
      // than the network allows. Raise it to saturate the connection on zoom.
      maplibregl.setMaxParallelImageRequests(32);

      const map = new maplibregl.Map({
        container: ref.current,
        style: styleFor(modeRef.current),
        center: points[0] ? [points[0].lon, points[0].lat] : [0, 20],
        zoom: points[0] ? 4 : 1.4,
        pitch: modeRef.current === "satellite" ? 62 : 0, // satellite is a 3D mode
        attributionControl: false,
        maxPitch: 85,
        fadeDuration: 0, // skip tile cross-fade for snappier loads
        refreshExpiredTiles: false,
        // Render CJK/Korean labels with a local font instead of fetching the huge
        // glyph PBF ranges over the network — faster first paint, far less data.
        localIdeographFontFamily: "sans-serif",
        // Don't repeat the world horizontally at low zoom: fewer duplicate tile
        // fetches and draws for the same ground.
        renderWorldCopies: false,
        // Bound the tile cache so long sessions / many pans don't grow GPU+RAM
        // unbounded (default scales with viewport, no hard ceiling).
        maxTileCacheSize: 256,
        // One map, multiple vector layers from one source — skip cross-source
        // label-collision checks we don't need; saves per-frame CPU.
        crossSourceCollisions: false,
      });
      if (globeRef.current) map.setProjection({ type: "globe" });
      mapRef.current = map;
      map.addControl(new maplibregl.NavigationControl({ visualizePitch: true }), "top-right");

      // Vector styles (Liberty/satellite POI layers) reference sprite icons we
      // don't ship. Without a sprite, MapLibre spams "Image X could not be
      // loaded". Register a 1×1 transparent pixel for any missing icon id so the
      // symbol layer renders its label without the icon and stays quiet.
      map.on("styleimagemissing", (e: { id: string }) => {
        if (!map.hasImage(e.id)) {
          map.addImage(e.id, { width: 1, height: 1, data: new Uint8Array(4) });
        }
      });

      // A single flaky raster/sprite tile (network hiccup, occasional 404, a
      // glyph that fails to decode) shouldn't surface as an uncaught error — the
      // map keeps working without it. Swallow asset-load errors, surface the rest.
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      map.on("error", (e: any) => {
        const msg: string = e?.error?.message || String(e?.error || "");
        if (/could not load image|image|tile|sprite|glyph|decode/i.test(msg)) return;
        console.warn("[map]", msg);
      });

      // Street-View pick: when armed, any click on the map opens Google Street
      // View at that exact spot in a new tab, then disarms. Lets the analyst walk
      // a street the AI/EXIF pinned and confirm it against the photo.
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      map.on("click", (e: any) => {
        if (!svModeRef.current) return;
        const { lat, lng } = e.lngLat;
        window.open(streetViewUrl(lat, lng), "_blank", "noopener,noreferrer");
        setSvMode(false);
      });

      // Attach/detach the terrain mesh as the camera tilts (cheap no-op when
      // already correct). Covers drag-pitch, easeTo, globe — all end in pitchend.
      map.on("pitchend", () => syncTerrain(map));

      map.on("load", () => {
        addAccuracy(map, points);
        syncTerrain(map); // satellite opens pre-tilted → build mesh on first paint

        // Markers are DOM overlays — they survive setStyle(), so add them once.
        const bounds = new maplibregl.LngLatBounds();
        for (const p of points) {
          const kind = p.kind ?? "geocoded";
          const exact = kind === "gps";
          const size = exact ? 13 : kind === "geocoded" ? 11 : 9;
          const el = document.createElement("div");
          // solid dot for exact fixes; hollow ring for estimates/coarse sources
          el.style.cssText = exact
            ? `width:${size}px;height:${size}px;border-radius:50%;background:#ffb000;box-shadow:0 0 0 2px #000,0 0 12px 3px rgba(255,176,0,.7);cursor:pointer`
            : `width:${size}px;height:${size}px;border-radius:50%;background:transparent;border:2px solid #ffb000;box-shadow:0 0 0 1px #000,0 0 10px 2px rgba(255,176,0,.45);cursor:pointer`;
          const corr =
            p.corroboration && p.corroboration > 1
              ? `<br/><b>✓ ${p.corroboration} sources agree</b>`
              : "";
          const acc = p.radiusKm
            ? `<br/>±${p.radiusKm < 1 ? `${Math.round(p.radiusKm * 1000)} m` : `${Math.round(p.radiusKm)} km`}`
            : "";
          const elev = typeof p.elevationM === "number" ? ` · ⛰ ${p.elevationM} m ASL` : "";
          // Google Maps directions + Street View to this point (lat/lon are numbers — safe).
          const dirUrl = `https://www.google.com/maps/dir/?api=1&destination=${p.lat},${p.lon}`;
          const svUrl = streetViewUrl(p.lat, p.lon);
          const btn = "display:inline-block;margin-top:6px;margin-right:5px;padding:3px 8px;text-decoration:none;border-radius:3px;font-weight:600";
          const popup = new maplibregl.Popup({ offset: 14, closeButton: false }).setHTML(
            `<div style="font:11px ui-monospace,monospace;color:#000">
               <b>${esc(p.label)}</b><br/>${esc((p.sources ?? [p.source]).join(", "))} · ${esc(kind)} · ${Math.round(p.confidence * 100)}%${corr}${acc}${elev}<br/>${p.lat.toFixed(4)}, ${p.lon.toFixed(4)}
               <br/><a href="${svUrl}" target="_blank" rel="noreferrer" style="${btn};background:#ffb000;color:#000">Street View</a><a href="${dirUrl}" target="_blank" rel="noreferrer" style="${btn};background:#000;color:#fff">Directions →</a>
             </div>`,
          );
          new maplibregl.Marker({ element: el }).setLngLat([p.lon, p.lat]).setPopup(popup).addTo(map);
          bounds.extend([p.lon, p.lat]);
        }
        if (points.length > 1) map.fitBounds(bounds, { padding: 60, maxZoom: 8, duration: 0 });
      });
    })();

    return () => {
      cancelled = true;
      mapRef.current?.remove();
      mapRef.current = null;
    };
  }, [points]);

  function changeMode(next: MapMode) {
    const map = mapRef.current;
    if (!map || next === mode) return;

    setMode(next);
    map.setStyle(styleFor(next), { diff: false });
    // setStyle wipes custom sources/layers — re-add accuracy rings once the new
    // style finishes loading. Markers (DOM) persist on their own.
    const onData = () => {
      if (!map.isStyleLoaded()) return;
      addAccuracy(map, points);
      syncTerrain(map); // new style re-added the DEM source — restore mesh if tilted
      map.setProjection({ type: globe ? "globe" : "mercator" }); // keep projection
      map.off("styledata", onData);
    };
    map.on("styledata", onData);

    // satellite is a 3D mode — tilt in so terrain + buildings read immediately;
    // flatten again when leaving it.
    if (next === "satellite") map.easeTo({ pitch: 62, duration: 900 });
    else if (mode === "satellite") map.easeTo({ pitch: 0, duration: 700 });
  }

  function toggle() {
    const map = mapRef.current;
    if (!map) return;
    const next = !globe;
    setGlobe(next);
    map.setProjection({ type: next ? "globe" : "mercator" });
  }

  function flyToFirst() {
    const map = mapRef.current;
    if (!map || !points[0]) return;
    map.flyTo({ center: [points[0].lon, points[0].lat], zoom: 16, pitch: 60, duration: 2500 });
  }

  if (!points.length) {
    return (
      <div className="flex min-h-[320px] flex-col items-center justify-center gap-3 rounded-lg border border-dashed border-border bg-panel p-10 text-center">
        <span className="font-display text-4xl italic text-muted">No fix</span>
        <p className="max-w-md text-sm leading-relaxed text-muted">
          Couldn&apos;t place this image. Fixes come from embedded GPS, AI
          estimates of the pixel content, reverse image search, and geocoded place
          names — this photo gave none of them enough to go on.
        </p>
      </div>
    );
  }

  const attribution =
    mode === "satellite"
      ? "Imagery © Esri · Buildings © OpenStreetMap · Elevation © AWS — tilt for 3D"
      : mode === "streets"
        ? "© OpenStreetMap · OpenFreeMap"
        : "© OpenStreetMap · OpenFreeMap · Elevation © AWS · tilt for 3D terrain";

  return (
    <div className="space-y-3">
    <div className="reticle relative overflow-hidden rounded-md border-2 border-border">
      <div
        ref={ref}
        className={`h-[68vh] max-h-[820px] min-h-[520px] w-full bg-neutral-900 ${
          mode === "recon" ? "[filter:grayscale(1)_contrast(1.02)_brightness(1.3)]" : ""
        }`}
      />

      {/* basemap mode switcher — segmented control */}
      <div className="absolute left-4 top-4 z-10 flex overflow-hidden rounded-sm border border-border bg-black/75 backdrop-blur">
        {MODES.map((m) => (
          <button
            key={m.id}
            onClick={() => changeMode(m.id)}
            className={`chip px-3.5 py-2 transition ${
              mode === m.id ? "bg-accent text-black" : "text-foreground hover:text-accent"
            }`}
          >
            {m.label}
          </button>
        ))}
      </div>

      <div className="absolute left-4 top-[3.65rem] z-10 flex gap-2">
        <button
          onClick={toggle}
          className="chip rounded-sm border border-border bg-black/75 px-3.5 py-2 text-foreground backdrop-blur transition hover:border-accent hover:text-accent"
        >
          {globe ? "▣ Flat 2D" : "◉ Globe 3D"}
        </button>
        <button
          onClick={flyToFirst}
          className="chip rounded-sm border border-border bg-black/75 px-3.5 py-2 text-foreground backdrop-blur transition hover:border-accent hover:text-accent"
        >
          ⛶ Zoom in
        </button>
        <button
          onClick={() => setSvMode((v) => !v)}
          title="Toggle, then click anywhere on the map to open Google Street View there"
          className={`chip rounded-sm border px-3.5 py-2 backdrop-blur transition ${
            svMode
              ? "border-accent bg-accent text-black"
              : "border-border bg-black/75 text-foreground hover:border-accent hover:text-accent"
          }`}
        >
          {svMode ? "◎ Click a street…" : "◎ Street view"}
        </button>
      </div>

      <div className="absolute bottom-3 right-3 z-10 text-[10px] text-muted/70">
        {attribution}
      </div>
    </div>

    {/* per-location list with one-click Google Maps directions */}
    <div className="flex flex-wrap gap-2">
      {points.map((p, i) => {
        const dir = `https://www.google.com/maps/dir/?api=1&destination=${p.lat},${p.lon}`;
        return (
          <div
            key={`${p.lat},${p.lon},${i}`}
            className="flex items-center gap-3 rounded-sm border border-border bg-panel px-3 py-2 text-sm"
          >
            <button
              onClick={() => mapRef.current?.flyTo({ center: [p.lon, p.lat], zoom: 15, duration: 1500 })}
              className="max-w-[220px] truncate text-left text-foreground hover:text-accent"
              title="center map here"
            >
              {p.label}
            </button>
            <span className="text-[11px] text-muted">{Math.round(p.confidence * 100)}%</span>
            {typeof p.elevationM === "number" && (
              <span className="text-[11px] text-muted" title="ground elevation above sea level">
                ⛰ {p.elevationM} m
              </span>
            )}
            <a
              href={streetViewUrl(p.lat, p.lon)}
              target="_blank"
              rel="noreferrer"
              className="chip rounded-sm border border-accent/50 px-3 py-1 text-accent transition hover:bg-accent hover:text-black"
            >
              Street View
            </a>
            <a
              href={dir}
              target="_blank"
              rel="noreferrer"
              className="chip rounded-sm bg-accent px-3 py-1 text-black transition hover:brightness-110"
            >
              Directions →
            </a>
          </div>
        );
      })}
    </div>
    </div>
  );
}
