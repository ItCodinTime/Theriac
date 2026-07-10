"use client";

/**
 * Client-side PDF text extraction using pdf.js.
 *
 * The backend's server-side extractor (pypdf) frequently returns little or no
 * text even for PDFs whose text is visually selectable (missing ToUnicode maps,
 * unusual encodings, etc.). pdf.js is the same engine browsers use to render
 * selectable text, so extracting here is dramatically more reliable. We then
 * hand the clean text straight to /agent/run and skip server-side parsing.
 */

// Loaded lazily so pdf.js never runs during SSR / build. We use the *legacy*
// build, which is transpiled for broad browser support (Safari/WebKit and older
// engines) — the default build uses newer JS that some browsers choke on with
// "undefined is not a function".
type PdfjsModule = typeof import("pdfjs-dist");
let pdfjsPromise: Promise<PdfjsModule> | null = null;

async function loadPdfjs(): Promise<PdfjsModule> {
  if (!pdfjsPromise) {
    pdfjsPromise = import("pdfjs-dist/legacy/build/pdf.mjs").then((mod) => {
      const pdfjs = mod as unknown as PdfjsModule;
      pdfjs.GlobalWorkerOptions.workerSrc = new URL(
        "pdfjs-dist/legacy/build/pdf.worker.min.mjs",
        import.meta.url,
      ).toString();
      return pdfjs;
    });
  }
  return pdfjsPromise;
}

/**
 * Bound a (possibly huge) manual down to the parts that matter for policy
 * extraction, so we never send a 500k-char payload that blows past the model's
 * context window and times out the backend (HTTP 502).
 *
 * Keeps the head (device model / firmware usually live up front) plus windows
 * of text around every network/port keyword hit, up to `maxChars`.
 */
export function curateManualText(text: string, maxChars = 16000): string {
  if (text.length <= maxChars) return text;

  const head = text.slice(0, 2500);
  let used = head.length;
  const windows: string[] = [];
  const seenBuckets = new Set<number>();
  const keyword =
    /(port\s*\d|\bports?\b|\btcp\b|\budp\b|protocol|firewall|network|ethernet|\blan\b|rs-?232|dicom|hl7)/gi;

  let match: RegExpExecArray | null;
  while ((match = keyword.exec(text)) !== null && used < maxChars) {
    const start = Math.max(0, match.index - 400);
    const bucket = Math.floor(start / 800);
    if (seenBuckets.has(bucket)) continue;
    seenBuckets.add(bucket);
    const chunk = text.slice(start, match.index + 400);
    windows.push(chunk);
    used += chunk.length;
  }

  return `${head}\n...\n${windows.join("\n...\n")}`.slice(0, maxChars);
}

/** Extract all text from a PDF file in the browser. Returns normalized text. */
export async function extractPdfText(file: File): Promise<string> {
  const pdfjs = await loadPdfjs();
  const data = new Uint8Array(await file.arrayBuffer());
  const loadingTask = pdfjs.getDocument({ data });
  const doc = await loadingTask.promise;

  try {
    const pages: string[] = [];
    for (let pageNum = 1; pageNum <= doc.numPages; pageNum++) {
      const page = await doc.getPage(pageNum);
      const content = await page.getTextContent();
      const line = content.items
        .map((item) => ("str" in item ? item.str : ""))
        .join(" ");
      pages.push(line);
      page.cleanup();
    }
    return pages
      .join("\n\n")
      .replace(/[ \t]+/g, " ")
      .replace(/\n{3,}/g, "\n\n")
      .trim();
  } finally {
    await loadingTask.destroy();
  }
}
