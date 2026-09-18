import type { Source, Finding } from "../types";
import { imageMediaType, safeFetch } from "../util";
import { prepareVisionImage } from "../vision";

// Reverse image search — the strongest "find where this photo came from" signal.
// Hosts the uploaded image on a free no-key host (catbox) to get a public URL,
// then builds one-click URL-based reverse-search links for the major engines.
//
// Why it serves GEOLOCATION: Yandex and Google Lens are excellent at matching a
// photo to its ORIGINAL post (often Instagram/Flickr/news). That source post
// frequently carries a location tag or caption — i.e. ground-truth coordinates
// the pixel-only AI estimate can only approximate. Parsing those results needs a
// paid API (SerpApi/Bing), out of the free scope, so we hand off clickable
// searches and the user reads the geotag off the matched post.
//
// PRIVACY: this uploads the image to a public third-party host. Disable with
// REVERSE_IMAGE_UPLOAD=0 if the subject image must not leave your control.

const q = (s: string) => encodeURIComponent(s);

// The upload is a leaf (it doesn't feed the map) but the response still waits for
// it, so bound it tightly; on timeout the user gets the manual-upload links.
const UPLOAD_TIMEOUT_MS = 8000;

export async function hostImage(
  buf: Buffer,
  name: string,
  signal?: AbortSignal,
  mediaType = imageMediaType(name),
): Promise<string | null> {
  try {
    const fd = new FormData();
    fd.append("reqtype", "fileupload");
    fd.append("fileToUpload", new Blob([new Uint8Array(buf)], { type: mediaType }), name);
    const res = await safeFetch(
      "https://catbox.moe/user/api.php",
      { method: "POST", body: fd },
      UPLOAD_TIMEOUT_MS,
      signal,
    );
    if (!res.ok) return null;
    const url = (await res.text()).trim();
    return /^https?:\/\//.test(url) ? url : null;
  } catch {
    return null;
  }
}

const reverseSource: Source = {
  id: "reverse-image",
  label: "Reverse Image Search",
  handles: ["image"],
  async run(e, ctx) {
    if (process.env.REVERSE_IMAGE_UPLOAD === "0") return [];
    const buf = ctx.images?.[e.value];
    if (!buf) return [];

    // Upload the (memoized) vision-prepared copy: phone photos are 5–12 MB, the
    // prepared JPEG is capped for the vision APIs and plenty for reverse search.
    const prepared = await prepareVisionImage(buf, e.value).catch(() => null);
    const jpegName =
      prepared?.mediaType === "image/jpeg" && !/\.jpe?g$/i.test(e.value)
        ? `${e.value.replace(/\.[^.]+$/, "")}.jpg`
        : e.value;
    const url = prepared
      ? await hostImage(prepared.data, jpegName, ctx.signal, prepared.mediaType)
      : await hostImage(buf, e.value, ctx.signal);
    if (!url) {
      return [
        {
          source: "reverse-image",
          image: e.value,
          title: `Reverse search for ${e.value} (manual)`,
          severity: "info",
          detail:
            "Auto-host failed — upload the image manually at these engines to find the source post (and its geotag).",
          data: {
            links: [
              { label: "Yandex Images (best for geo)", url: "https://yandex.com/images/" },
              { label: "Google Lens", url: "https://lens.google.com/" },
              { label: "Bing Visual", url: "https://www.bing.com/visualsearch" },
              { label: "TinEye", url: "https://tineye.com/" },
            ],
          },
        },
      ];
    }

    return [
      {
        source: "reverse-image",
        image: e.value,
        title: `Reverse image search ready: ${e.value}`,
        severity: "low",
        url,
        detail:
          "Image hosted publicly to enable URL-based reverse search. Open Yandex/Lens first — they best surface the original (often geotagged) post.",
        data: {
          hostedImage: url,
          links: [
            { label: "Yandex (best for geo)", url: `https://yandex.com/images/search?rpt=imageview&url=${q(url)}` },
            { label: "Google Lens", url: `https://lens.google.com/uploadbyurl?url=${q(url)}` },
            { label: "Bing Visual", url: `https://www.bing.com/images/searchbyimage?cbir=sbi&imgurl=${q(url)}` },
            { label: "TinEye", url: `https://www.tineye.com/search?url=${q(url)}` },
          ],
          tip: "If a match is an Instagram/Flickr/news post, open it and read its location tag — that's a ground-truth fix.",
          privacy: "Image was uploaded to catbox.moe (public). Set REVERSE_IMAGE_UPLOAD=0 to disable.",
        },
      } as Finding,
    ];
  },
};

export default reverseSource;
