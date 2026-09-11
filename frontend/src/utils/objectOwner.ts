/** Human-readable label from API owner_sub (e.g. local:alice → alice). */
export function formatOwnerSub(ownerSub?: string | null): string {
  if (!ownerSub) return "";
  if (ownerSub.startsWith("local:")) return ownerSub.slice("local:".length);
  return ownerSub;
}
