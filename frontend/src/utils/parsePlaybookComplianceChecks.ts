export type PlaybookComplianceCheck = {
  rule: string;
  status: "pass" | "fail" | "skip" | "error";
  summary: string;
  detail: string;
  message: string;
};

// Non-global: safe for repeated .exec/.search without lastIndex races.
const CHECK_LINE_RE =
  /^(PASS|FAIL|SKIP|ERROR|NA|N\/?A)\|([^|]+)\|([^|]*)\|(.*)$/i;

// Global scanner for embedded rows inside a large dump. Do not share with CHECK_LINE_RE.
const CHECK_LINE_SCAN_RE =
  /(PASS|FAIL|SKIP|ERROR|NA|N\/?A)\|([^|"\s]+)\|([^|]*)\|([^|"]*?)(?=(?:"|,|\s*\]|$))/gi;

function normalizeStatus(raw: string): PlaybookComplianceCheck["status"] {
  const key = raw.trim().toUpperCase().replace("/", "");
  if (key === "PASS") return "pass";
  if (key === "FAIL") return "fail";
  if (key === "SKIP" || key === "NA") return "skip";
  return "error";
}

function buildMessage(summary: string, detail: string): string {
  const s = summary.trim();
  const d = detail.trim();
  if (s && d) return `${s}: ${d}`;
  return s || d;
}

function appendCheck(
  bucket: Map<string, PlaybookComplianceCheck>,
  statusRaw: string,
  ruleRaw: string,
  summary: string,
  detail: string
): void {
  const rule = ruleRaw.trim();
  if (!rule) return;
  bucket.set(rule, {
    rule,
    status: normalizeStatus(statusRaw),
    summary: summary.trim(),
    detail: detail.trim(),
    message: buildMessage(summary, detail),
  });
}

function ingestCheckLine(bucket: Map<string, PlaybookComplianceCheck>, line: string): void {
  const match = CHECK_LINE_RE.exec(line.trim());
  if (!match) return;
  appendCheck(bucket, match[1], match[2], match[3] ?? "", match[4] ?? "");
}

function tryParseJsonBlob(text: string): unknown | null {
  let start = -1;
  for (let i = 0; i < text.length; i++) {
    if (text[i] === "{" || text[i] === "[") {
      start = i;
      break;
    }
  }
  if (start < 0) return null;

  let depth = 0;
  let inString = false;
  let escape = false;
  for (let i = start; i < text.length; i++) {
    const ch = text[i];
    if (inString) {
      if (escape) {
        escape = false;
        continue;
      }
      if (ch === "\\") {
        escape = true;
        continue;
      }
      if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') {
      inString = true;
      continue;
    }
    if (ch === "{" || ch === "[") depth += 1;
    else if (ch === "}" || ch === "]") {
      depth -= 1;
      if (depth === 0) {
        try {
          return JSON.parse(text.slice(start, i + 1));
        } catch {
          return null;
        }
      }
    }
  }
  return null;
}

function walkForChecks(bucket: Map<string, PlaybookComplianceCheck>, node: unknown): void {
  if (node == null) return;
  if (Array.isArray(node)) {
    if (node.length > 0 && node.every((item) => typeof item === "string")) {
      for (const item of node) ingestCheckLine(bucket, item);
      return;
    }
    for (const item of node) walkForChecks(bucket, item);
    return;
  }
  if (typeof node !== "object") return;
  const record = node as Record<string, unknown>;
  const checks = record.checks;
  if (Array.isArray(checks)) {
    for (const item of checks) {
      if (typeof item === "string") ingestCheckLine(bucket, item);
    }
  } else if (typeof checks === "string") {
    ingestCheckLine(bucket, checks);
    const nested = tryParseJsonBlob(checks);
    if (nested != null) walkForChecks(bucket, nested);
  }
  for (const [key, value] of Object.entries(record)) {
    if (key === "checks") continue;
    walkForChecks(bucket, value);
  }
}

function scanEmbeddedCheckLines(bucket: Map<string, PlaybookComplianceCheck>, text: string): void {
  // Fresh regex instance so callers never share lastIndex state.
  const scanner = new RegExp(CHECK_LINE_SCAN_RE.source, CHECK_LINE_SCAN_RE.flags);
  let match: RegExpExecArray | null;
  while ((match = scanner.exec(text)) !== null) {
    appendCheck(bucket, match[1], match[2], match[3] ?? "", match[4] ?? "");
    // Guard against zero-length matches advancing forever.
    if (match[0].length === 0) scanner.lastIndex += 1;
  }
}

/** Extract CRE STATUS|rule|summary|detail rows from Ansible playbook output. */
export function parsePlaybookComplianceChecks(output: string | null | undefined): PlaybookComplianceCheck[] {
  const text = (output ?? "").trim();
  if (!text) return [];

  const bucket = new Map<string, PlaybookComplianceCheck>();

  for (const line of text.split("\n")) {
    const payload = tryParseJsonBlob(line);
    if (payload != null) {
      walkForChecks(bucket, payload);
      continue;
    }
    // Fallback for plain STATUS|... lines outside JSON.
    ingestCheckLine(bucket, line);
  }

  // Truncated JSON dumps may still contain complete quoted check rows.
  if (bucket.size === 0) {
    scanEmbeddedCheckLines(bucket, text);
  }

  return [...bucket.values()].sort((a, b) => a.rule.localeCompare(b.rule));
}
