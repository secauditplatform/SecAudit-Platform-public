import type { ReactNode } from "react";
import type { ProfileRule } from "../api/client";
import {
  formatProfileRuleSeverityLabel,
  getProfileRuleSeverityBucket,
  resolveProfileRuleSeverity,
} from "../utils/profileRuleSeverity";

export type ProfileRuleMetadataFields = Pick<
  ProfileRule,
  "title" | "explanation" | "impact" | "scope" | "scap_rule_id" | "criticality"
>;

export function ProfileRuleMetaRow({
  label,
  value,
  kind,
}: {
  label: string;
  value?: string | null;
  kind?: "description" | "risk" | "location" | "scap";
}) {
  if (!value?.trim()) return null;
  return (
    <div className={`pf-profile-rule__meta-row${kind ? ` pf-profile-rule__meta-row--${kind}` : ""}`}>
      <span className="pf-profile-rule__meta-label">{label}</span>
      <p className="pf-profile-rule__meta-value">{value}</p>
    </div>
  );
}

export function ProfileRuleSeverityChip({
  rule,
}: {
  rule?: Pick<ProfileRule, "criticality"> | null;
}) {
  const severity = resolveProfileRuleSeverity(rule);
  const bucket = getProfileRuleSeverityBucket(rule);
  if (!severity || !bucket) return null;

  return (
    <span
      className={`pf-profile-rule__severity-chip pf-profile-rule__severity-chip--${bucket}`}
      title={severity}
    >
      {formatProfileRuleSeverityLabel(severity)}
    </span>
  );
}

/** True when the expanded body has fields beyond the accordion title. */
export function hasProfileRuleMetadata(rule?: ProfileRuleMetadataFields | null): boolean {
  return Boolean(
    rule?.explanation?.trim() ||
      rule?.impact?.trim() ||
      rule?.scope?.trim() ||
      rule?.scap_rule_id?.trim()
  );
}

export type ProfileRuleLookup = Pick<ProfileRule, "tech_name" | "requirement_id"> &
  ProfileRuleMetadataFields;

export function findProfileRule(
  rules: readonly ProfileRuleLookup[] | undefined,
  ruleTechName: string
): ProfileRuleLookup | undefined {
  if (!rules?.length) return undefined;
  const byRequirement = rules.find((rule) => rule.requirement_id === ruleTechName);
  if (byRequirement) return byRequirement;
  return rules.find((rule) => rule.tech_name === ruleTechName);
}

/** Human-readable check name (title preferred; identity fallback). */
export function profileRuleDisplayName(
  rule: Pick<ProfileRule, "title" | "tech_name" | "requirement_id">
): string {
  const title = rule.title?.trim();
  if (title) {
    return title.replace(/^\d+(?:\.\d+)*\s+/, "").replace(/\s*\(.*?\)\s*$/, "").trim() || title;
  }
  return rule.requirement_id || rule.tech_name || "";
}

export function ProfileRuleMetadata({
  rule,
  labels,
  toolbar,
}: {
  rule?: ProfileRuleMetadataFields | null;
  labels: {
    description: string;
    risk: string;
    location: string;
    scapRuleId?: string;
  };
  toolbar?: ReactNode;
}) {
  const hasImpact = Boolean(rule?.impact?.trim());
  const hasScope = Boolean(rule?.scope?.trim());
  const hasSide = hasImpact || hasScope;

  return (
    <div className="pf-profile-rule__meta">
      {toolbar}
      <ProfileRuleMetaRow kind="description" label={labels.description} value={rule?.explanation} />
      {hasSide ? (
        <div className="pf-profile-rule__meta-aside">
          <ProfileRuleMetaRow kind="risk" label={labels.risk} value={rule?.impact} />
          <ProfileRuleMetaRow kind="location" label={labels.location} value={rule?.scope} />
        </div>
      ) : null}
      {labels.scapRuleId ? (
        <ProfileRuleMetaRow kind="scap" label={labels.scapRuleId} value={rule?.scap_rule_id} />
      ) : null}
    </div>
  );
}
