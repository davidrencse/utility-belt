import type { Source, Entity } from "../types";
import { entity } from "../util";
import { compass8 } from "../geo";

const exifSource: Source = {
  id: "exif",
  label: "Image EXIF / Metadata",
  handles: ["image"],
  async run(e, ctx) {
    const buf = ctx.images?.[e.value];
    if (!buf) return [];
    const exifr = (await import("exifr")).default;

    let meta: Record<string, unknown> | undefined;
    try {
      // Targeted parse: only the blocks we actually read (EXIF/GPS/IPTC/XMP).
      // Skipping makerNote/interop/thumbnail avoids the slowest decode paths.
      meta = (await exifr.parse(buf, {
        tiff: true,
        exif: true,
        gps: true,
        iptc: true,
        xmp: true,
        interop: false,
        makerNote: false,
        translateKeys: true,
        translateValues: true,
        reviveValues: true,
        mergeOutput: true,
      })) as Record<string, unknown> | undefined;
    } catch {
      return [];
    }
    if (!meta) {
      return [
        {
          source: "exif",
          image: e.value,
          title: `No EXIF metadata in ${e.value}`,
          severity: "info",
          detail: "Image carries no embedded metadata (may have been stripped).",
        },
      ];
    }

    const newEntities: Entity[] = [];
    const lat = meta.latitude as number | undefined;
    const lon = meta.longitude as number | undefined;
    // Ground-truth camera heading: GPSImgDirection is the compass bearing the lens
    // pointed when the shutter fired (GPSImgDirectionRef = T true / M magnetic).
    // This is a MEASURED bearing — strictly better than the AI's perspective-guess
    // in geovision — so surface it directly.
    const imgDir = meta.GPSImgDirection as number | undefined;
    const dirRef = (meta.GPSImgDirectionRef as string | undefined) === "M" ? "magnetic" : "true";
    const altitude = meta.GPSAltitude as number | undefined;
    if (lat != null && lon != null) {
      const bearingNote =
        typeof imgDir === "number" ? ` · facing ${compass8(imgDir)} (${Math.round(imgDir)}°)` : "";
      newEntities.push(
        entity("location", `${lat}, ${lon}`, "exif", 0.9, {
          label: `GPS from photo${bearingNote}`,
          meta: {
            lat,
            lon,
            radiusKm: 0.03,
            kind: "gps",
            map: `https://www.google.com/maps?q=${lat},${lon}`,
            ...(typeof imgDir === "number" ? { bearingDeg: imgDir } : {}),
          },
        }),
      );
    }

    // IPTC / XMP embedded place names (present in many photos even without GPS).
    // Field names vary across writers — check the common variants.
    const pick = (...keys: string[]) => {
      for (const k of keys) {
        const v = meta?.[k];
        if (typeof v === "string" && v.trim()) return v.trim();
      }
      return undefined;
    };
    const city = pick("City");
    const state = pick("State", "Province/State", "ProvinceState");
    const country = pick("Country", "Country/PrimaryLocationName", "CountryPrimaryLocationName", "CountryCode");
    const sublocation = pick("Sub-location", "Sublocation", "Location");
    const placeText = [sublocation, city, state, country].filter(Boolean).join(", ");

    // Only emit a text location when we don't already have exact GPS — geocode
    // source will turn this text into coords for the map.
    if (placeText && lat == null) {
      newEntities.push(
        entity("location", placeText, "exif", 0.7, { label: "IPTC/XMP place tag" }),
      );
    }

    const camera = [meta.Make, meta.Model].filter(Boolean).join(" ");
    const sw = meta.Software as string | undefined;

    return [
      {
        source: "exif",
        image: e.value,
        title: `EXIF metadata for ${e.value}`,
        severity: lat != null || placeText ? "medium" : "low",
        data: {
          gps: lat != null ? { lat, lon, map: `https://www.google.com/maps?q=${lat},${lon}` } : undefined,
          cameraBearing:
            typeof imgDir === "number"
              ? `${compass8(imgDir)} ${Math.round(imgDir)}° (${dirRef})`
              : undefined,
          altitude: typeof altitude === "number" ? `${Math.round(altitude)} m` : undefined,
          place: placeText || undefined,
          camera: camera || undefined,
          software: sw,
          taken: (meta.DateTimeOriginal as Date | undefined)?.toString?.(),
          dimensions:
            meta.ImageWidth && meta.ImageHeight
              ? `${meta.ImageWidth}x${meta.ImageHeight}`
              : undefined,
          artist: meta.Artist,
          copyright: meta.Copyright,
        },
        entities: newEntities,
      },
    ];
  },
};

export default exifSource;
