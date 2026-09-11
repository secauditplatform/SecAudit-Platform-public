type LocationLike = Pick<Location, "protocol" | "host">;

function sameOriginWsBase(location: LocationLike): string {
  const protocol = location.protocol === "https:" ? "wss:" : "ws:";
  return `${protocol}//${location.host}`;
}

/**
 * Resolve the WebSocket API base URL.
 * Uses VITE_WS_URL when set; otherwise derives ws:/wss: from the page origin
 * so HTTPS pages never default to insecure ws:// (mixed content).
 *
 * If an override is `ws://` while the page is HTTPS, upgrade to `wss://`
 * (same host/path) to avoid mixed-content blocks. Prefer leaving VITE_WS_URL
 * unset so the browser uses same-origin (Vite proxies `/api` WS in dev).
 *
 * Pass `null` or `""` to force the same-origin default (ignores VITE_WS_URL).
 * Omit the first argument (or pass `undefined`) to honor VITE_WS_URL.
 */
export function resolveWsBaseUrl(
  envUrl?: string | null,
  location: LocationLike = typeof window !== "undefined"
    ? window.location
    : { protocol: "http:", host: "localhost" }
): string {
  const raw = envUrl === undefined ? import.meta.env.VITE_WS_URL : envUrl;
  const trimmed = typeof raw === "string" ? raw.trim() : "";
  if (!trimmed) {
    return sameOriginWsBase(location);
  }

  let base = trimmed.replace(/\/$/, "");
  // Protocol-relative override: inherit page scheme (https → wss, else ws).
  if (base.startsWith("//")) {
    const protocol = location.protocol === "https:" ? "wss:" : "ws:";
    return `${protocol}${base}`;
  }
  // Avoid mixed content when a misconfigured ws:// override is used under HTTPS.
  if (location.protocol === "https:" && base.startsWith("ws://")) {
    base = `wss://${base.slice("ws://".length)}`;
  }
  return base;
}
