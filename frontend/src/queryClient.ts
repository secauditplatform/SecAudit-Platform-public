import { QueryClient } from "@tanstack/react-query";

/** Shared client so auth logout can clear cache even when TokenSync is unmounted. */
export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 2,
      refetchOnWindowFocus: true,
      refetchOnReconnect: true,
    },
  },
});
