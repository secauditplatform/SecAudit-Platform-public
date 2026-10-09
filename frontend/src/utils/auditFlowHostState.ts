import type { AuditFlowHost, AuditFlowRun } from "../api/client";

export const CLEARABLE_SKIP_REASONS = new Set([
  "auth_failed",
  "unreachable",
  "no_matching_profile",
  "skipped_by_user",
  "low_confidence",
  "ambiguous_profile",
  "os_mismatch",
  "checking",
]);

export function clearRetryableSkip(host: AuditFlowHost): AuditFlowHost {
  if (!host.skip_reason || !CLEARABLE_SKIP_REASONS.has(host.skip_reason)) {
    return host;
  }
  return { ...host, skip_reason: null, skip_detail: null };
}

/** Review-step readiness: profile + credential required before a host is "available". */
export function hostReviewReason(host: AuditFlowHost): string | null {
  if (host.skip_reason && host.skip_reason !== "skipped_by_user") {
    if (host.skip_reason === "unreachable") {
      if (!host.profile_id && !host.os_guess) {
        return "no_matching_profile";
      }
    } else if (!(host.skip_reason === "no_matching_profile" && host.profile_id)) {
      // Manual profile assignment resolves auto-match failures.
      return host.skip_reason;
    }
  }

  if (host.selected && !host.job_run_id) {
    if (!host.profile_id) {
      return host.skip_reason ?? "no_matching_profile";
    }
    if (!host.credential_id) {
      return "missing_credential";
    }
  }

  return host.skip_reason && host.skip_reason !== "no_matching_profile"
    ? host.skip_reason
    : null;
}

export function applyAuditFlowHostPatch(
  run: AuditFlowRun,
  payload: {
    id: number;
    selected?: boolean;
    profile_id?: number | null;
    credential_id?: number | null;
    profile_name?: string | null;
  }
): AuditFlowRun {
  return {
    ...run,
    hosts: run.hosts.map((host) => {
      if (host.id !== payload.id) return host;
      let next: AuditFlowHost = { ...host };

      if (payload.selected !== undefined) {
        next.selected = payload.selected;
        if (!host.job_run_id) {
          if (payload.selected) {
            if (host.skip_reason === "skipped_by_user") {
              next = clearRetryableSkip(next);
            }
          } else {
            next.skip_reason = "skipped_by_user";
            next.skip_detail = "Not selected for compliance";
          }
        }
      }

      if (payload.profile_id !== undefined) {
        if (payload.profile_id === null) {
          next.profile_id = null;
          next.profile_name = null;
          next.confidence = 0;
          if (!host.job_run_id) {
            next.selected = false;
            next.skip_reason = "skipped_by_user";
            next.skip_detail = "Not selected for compliance";
          }
        } else {
          next.profile_id = payload.profile_id;
          next.profile_name = payload.profile_name ?? host.profile_name;
          next.confidence = 100;
          next.selected = true;
          next = clearRetryableSkip(next);
        }
      }

      if (payload.credential_id !== undefined) {
        if (payload.credential_id === null) {
          next.credential_id = null;
          next.credential_label = null;
        } else {
          next.credential_id = payload.credential_id;
          next.selected = true;
          next = clearRetryableSkip(next);
        }
      }

      return next;
    }),
  };
}
