import { setAuthToken } from "../api/client";
import { queryClient } from "../queryClient";

/**
 * Drop the module-level bearer and any cached authenticated queries.
 * Must run on logout / session invalidation because AuthProvider unmounts
 * TokenSync when rendering the login page, so TokenSync alone cannot clear.
 */
export function clearAuthArtifacts(): void {
  setAuthToken(null);
  queryClient.clear();
}

/**
 * Whether React Query cache should be cleared for an identity transition.
 * Uses a stable identity (e.g. username), not the raw JWT, so token refresh
 * does not wipe the cache. Skips the first mount (previous === undefined).
 */
export function shouldClearQueryCacheOnIdentityChange(
  previousIdentity: string | null | undefined,
  nextIdentity: string | null
): boolean {
  if (previousIdentity === undefined) return false;
  return previousIdentity !== nextIdentity;
}
