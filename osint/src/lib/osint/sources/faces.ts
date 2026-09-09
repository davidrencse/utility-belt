import type { Source, Finding, Severity, Box } from "../types";
import { cleanBox } from "../util";
import { analyzeImageJson, visionConfig } from "../vision";

// AI face-attribute estimation. Detects visible faces and estimates SOFT
// biometric attributes (perceived gender, age range, emotion, apparent
// ethnicity, accessories). Provider-agnostic — same vision backend as geovision.
//
// These are probabilistic AI GUESSES, not facts, and are frequently wrong —
// labelled as such in the output. This estimates attributes only; it does NOT
// attempt to identify *who* a person is (no name/identity matching).

const PROMPT = `You are a forensic image analyst. Detect every clearly visible HUMAN FACE in the image and, for each, give your best visual ESTIMATE of soft attributes. These are uncertain guesses from pixels alone — never claim certainty, and do NOT try to identify who the person is (no names/identity).
For each face estimate:
- box: the face's bounding box as fractions of image size: {x,y,w,h} where x,y is the TOP-LEFT corner and w,h the width/height, each 0..1 (x+w ≤ 1, y+h ≤ 1). Be tight around the face.
- perceivedGender: "male" | "female" | "uncertain"
- ageRange: a rough bracket like "0-12","13-19","20-29","30-44","45-59","60+"
- emotion: dominant expression (e.g. neutral, happy, sad, angry, surprised, fearful)
- apparentEthnicity: broad visual guess (e.g. "East Asian","South Asian","Black","White","Hispanic/Latino","Middle Eastern","uncertain")
- features: notable visible items (glasses, beard, headwear, mask, etc.)
- confidence: 0..1 for THIS face's estimates overall
Respond with ONLY a JSON object, no prose, no code fences:
{"count":number,"faces":[{"box":{"x":number,"y":number,"w":number,"h":number},"perceivedGender":string,"ageRange":string,"emotion":string,"apparentEthnicity":string,"features":string[],"confidence":number}]}`;

interface FaceOut {
  count?: number;
  faces?: {
    box?: Partial<Box>;
    perceivedGender?: string;
    ageRange?: string;
    emotion?: string;
    apparentEthnicity?: string;
    features?: string[];
    confidence?: number;
  }[];
}

const sevFor = (c: number): Severity => (c >= 0.7 ? "medium" : "low");

const facesSource: Source = {
  id: "faces",
  label: "Face Attributes (AI)",
  handles: ["image"],
  requiresKey: "VISION_API_KEY",
  async run(e, ctx) {
    const buf = ctx.images?.[e.value];
    const cfg = visionConfig(ctx.keys);
    if (!buf || !cfg) return [];
    // Oversized images are downscaled in analyzeImageJson (prepareVisionImage).

    const o = await analyzeImageJson<FaceOut>({
      buffer: buf,
      filename: e.value,
      prompt: PROMPT,
      cfg,
      signal: ctx.signal,
    });

    const faces = (o.faces || []).filter((f) => f && (f.perceivedGender || f.ageRange || f.emotion));
    if (!faces.length) {
      return [
        { source: "faces", image: e.value, title: `No faces detected in ${e.value}`, severity: "info" },
      ];
    }

    const conf =
      faces.reduce((s, f) => s + (typeof f.confidence === "number" ? f.confidence : 0.3), 0) /
      faces.length;

    return [
      {
        source: "faces",
        image: e.value,
        title: `${faces.length} face${faces.length > 1 ? "s" : ""} analyzed in ${e.value}`,
        severity: sevFor(conf),
        data: {
          faces: faces.map((f, i) => ({
            face: i + 1,
            box: cleanBox(f.box),
            gender: f.perceivedGender || "uncertain",
            age: f.ageRange || "?",
            emotion: f.emotion || "?",
            ethnicity: f.apparentEthnicity || "uncertain",
            features: f.features?.length ? f.features.join(", ") : undefined,
            confidence: typeof f.confidence === "number" ? `${Math.round(f.confidence * 100)}%` : undefined,
          })),
          model: cfg.model,
          note: "AI estimates from pixels — perceived attributes only, often wrong. Not identity, not fact.",
        },
      } as Finding,
    ];
  },
};

export default facesSource;
