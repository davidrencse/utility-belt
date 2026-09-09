import { NextRequest, NextResponse } from "next/server";
import { geolocate } from "@/lib/osint/engine";

export const runtime = "nodejs";
export const maxDuration = 120;

// Upload limits. Untrusted clients control file size/count; without caps a
// request can exhaust memory.
const MAX_FILE_BYTES = 12 * 1024 * 1024; // per image
const MAX_FILES = 12;
const MAX_TOTAL_UPLOAD_BYTES = 40 * 1024 * 1024; // all images combined

export async function POST(req: NextRequest) {
  const ct = req.headers.get("content-type") || "";
  const images: Record<string, Buffer> = {};

  if (!ct.includes("multipart/form-data")) {
    return NextResponse.json({ error: "Upload images as multipart/form-data" }, { status: 400 });
  }

  try {
    const form = await req.formData();
    let total = 0;
    for (const [, val] of form.entries()) {
      if (!(val instanceof File) || val.size === 0) continue;
      if (!val.type.startsWith("image/")) continue;
      if (Object.keys(images).length >= MAX_FILES) break;
      if (val.size > MAX_FILE_BYTES) {
        return NextResponse.json(
          { error: `Image exceeds ${MAX_FILE_BYTES / 1e6}MB limit` },
          { status: 413 },
        );
      }
      total += val.size;
      if (total > MAX_TOTAL_UPLOAD_BYTES) {
        return NextResponse.json({ error: "Total upload size too large" }, { status: 413 });
      }
      const buf = Buffer.from(await val.arrayBuffer());
      images[val.name || `upload-${Object.keys(images).length}`] = buf;
    }
  } catch {
    return NextResponse.json({ error: "Invalid request body" }, { status: 400 });
  }

  if (!Object.keys(images).length) {
    return NextResponse.json({ error: "No images provided." }, { status: 400 });
  }

  try {
    const result = await geolocate({ images, signal: req.signal });
    return NextResponse.json(result);
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "Geolocation failed" },
      { status: 500 },
    );
  }
}
