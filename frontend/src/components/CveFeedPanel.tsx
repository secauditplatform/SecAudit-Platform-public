import { useMutation, useQueries, useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useRef, useState } from "react";
import {
  api,
  type CveFeedEntry,
  type CveFeedEntryInput,
  type CveFeedStatus,
  type Profile,
  type ProfileRule,
} from "../api/client";
import { useAuth } from "../auth/AuthProvider";
import { useTranslation } from "../i18n/I18nProvider";
import { Button } from "./ui/Button";
import { useConfirm } from "./ui/ConfirmDialog";
import { Panel } from "./ui/Panel";
import { useToast } from "./ui/Toast";

const CVE_ID_RE = /^CVE-\d{4}-\d{4,}$/i;

type Draft = {
  cve_id: string;
  requirement_id: string;
  profile_name: string;
  summary: string;
};

type Choice = { value: string; label: string };

function choiceLabel(value: string, title?: string | null): string {
  const extra = (title || "").trim();
  return extra && extra !== value ? `${value} — ${extra}` : value;
}

function sortedChoices(entries: Map<string, string>): Choice[] {
  return [...entries.entries()]
    .map(([value, label]) => ({ value, label }))
    .sort((left, right) => left.label.localeCompare(right.label));
}

function profileChoices(profiles: Profile[], feedNames: string[]): Choice[] {
  const seen = new Map<string, string>();
  for (const profile of profiles) {
    const value = profile.profile_name.trim();
    if (!value || seen.has(value)) continue;
    seen.set(value, choiceLabel(value, profile.profile_title));
  }
  for (const raw of feedNames) {
    const value = raw.trim();
    if (value && !seen.has(value)) seen.set(value, value);
  }
  return sortedChoices(seen);
}

function ruleChoices(
  profiles: Profile[],
  rulesByProfileId: Map<number, ProfileRule[]>,
  profileName: string,
  feedEntries: CveFeedEntry[]
): Choice[] {
  const name = profileName.trim();
  const matched = name ? profiles.filter((profile) => profile.profile_name === name) : profiles;
  const seen = new Map<string, string>();
  for (const profile of matched) {
    for (const rule of rulesByProfileId.get(profile.id) ?? []) {
      const value = (rule.tech_name || rule.requirement_id || "").trim();
      if (!value || seen.has(value)) continue;
      seen.set(value, choiceLabel(value, rule.title));
    }
  }
  for (const entry of feedEntries) {
    const value = entry.requirement_id.trim();
    const entryProfile = entry.profile_name.trim();
    if (!value || seen.has(value)) continue;
    if (name && entryProfile && entryProfile !== name) continue;
    seen.set(value, value);
  }
  return sortedChoices(seen);
}

const emptyDraft = (): Draft => ({
  cve_id: "",
  requirement_id: "",
  profile_name: "",
  summary: "",
});

function draftFromEntry(entry: CveFeedEntry): Draft {
  return {
    cve_id: entry.cve_id,
    requirement_id: entry.requirement_id,
    profile_name: entry.profile_name,
    summary: entry.summary ?? "",
  };
}

function draftPayload(draft: Draft): CveFeedEntryInput | "bad-id" | "need-target" {
  const cveId = draft.cve_id.trim();
  const requirementId = draft.requirement_id.trim();
  const profileName = draft.profile_name.trim();
  const summary = draft.summary.trim();
  if (!CVE_ID_RE.test(cveId)) return "bad-id";
  if (!requirementId && !profileName) return "need-target";
  return {
    cve_id: cveId,
    requirement_id: requirementId,
    profile_name: profileName,
    summary: summary || null,
  };
}

export function CveFeedPanel() {
  const { t, dateLocale } = useTranslation();
  const { isAdmin } = useAuth();
  const toast = useToast();
  const { confirm } = useConfirm();
  const queryClient = useQueryClient();
  const inputRef = useRef<HTMLInputElement>(null);
  const [adding, setAdding] = useState(false);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [draft, setDraft] = useState<Draft>(emptyDraft);

  const formOpen = adding || editingId != null;

  const status = useQuery({
    queryKey: ["cve-feed"],
    queryFn: api.cveFeedStatus,
    enabled: isAdmin,
  });

  const profilesQuery = useQuery({
    queryKey: ["profiles"],
    queryFn: () => api.profiles(),
    enabled: isAdmin && formOpen,
    staleTime: 120_000,
  });
  const profileList = profilesQuery.data ?? [];
  const rulesQueries = useQueries({
    queries: profileList.map((profile) => ({
      queryKey: ["profile-rules", profile.id],
      queryFn: () => api.getProfileRules(profile.id),
      enabled: isAdmin && formOpen,
      staleTime: 120_000,
    })),
  });

  const applyStatus = (next: CveFeedStatus, message: string) => {
    queryClient.setQueryData(["cve-feed"], next);
    queryClient.invalidateQueries({ queryKey: ["run-detail"] });
    setAdding(false);
    setEditingId(null);
    setDraft(emptyDraft());
    toast.success(message);
  };

  const replaceFeed = useMutation({
    mutationFn: api.replaceCveFeed,
    onSuccess: (next) => {
      applyStatus(next, next.loaded ? t("reports.cveFeedSaved") : t("reports.cveFeedCleared"));
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("reports.cveFeedInvalid")),
  });

  const clearFeed = useMutation({
    mutationFn: api.clearCveFeed,
    onSuccess: (next) => applyStatus(next, t("reports.cveFeedCleared")),
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const saveEntry = useMutation({
    mutationFn: async (payload: CveFeedEntryInput) => {
      if (editingId != null) return api.updateCveFeedEntry(editingId, payload);
      return api.createCveFeedEntry(payload);
    },
    onSuccess: (next) => {
      applyStatus(next, editingId != null ? t("reports.cveFeedEntrySaved") : t("reports.cveFeedEntryAdded"));
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("reports.cveFeedInvalid")),
  });

  const deleteEntry = useMutation({
    mutationFn: api.deleteCveFeedEntry,
    onSuccess: (next) => applyStatus(next, t("reports.cveFeedEntryDeleted")),
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const entries = status.data?.entries ?? [];
  const rulesByProfileId = useMemo(() => {
    const map = new Map<number, ProfileRule[]>();
    profileList.forEach((profile, index) => {
      const rules = rulesQueries[index]?.data;
      if (rules) map.set(profile.id, rules);
    });
    return map;
  }, [profileList, rulesQueries]);
  const profilesForPick = useMemo(
    () => profileChoices(profileList, entries.map((entry) => entry.profile_name)),
    [profileList, entries]
  );
  const rulesForPick = useMemo(
    () =>
      ruleChoices(profileList, rulesByProfileId, draft.profile_name, entries),
    [profileList, rulesByProfileId, draft.profile_name, entries]
  );
  const rulesLoading =
    formOpen && (profilesQuery.isLoading || rulesQueries.some((query) => query.isLoading));

  if (!isAdmin) return null;

  const loaded = Boolean(status.data?.loaded);
  const importedAt = status.data?.imported_at
    ? new Date(status.data.imported_at).toLocaleString(dateLocale)
    : null;
  const stats = useMemo(() => {
    let byRule = 0;
    let byProfile = 0;
    let both = 0;
    const cves = new Set<string>();
    for (const entry of entries) {
      cves.add(entry.cve_id);
      const hasRule = Boolean(entry.requirement_id.trim());
      const hasProfile = Boolean(entry.profile_name.trim());
      if (hasRule && hasProfile) both += 1;
      else if (hasRule) byRule += 1;
      else if (hasProfile) byProfile += 1;
    }
    return { total: entries.length, cves: cves.size, byRule, byProfile, both };
  }, [entries]);
  const busy = replaceFeed.isPending || clearFeed.isPending || saveEntry.isPending || deleteEntry.isPending;

  const onFile = async (file: File | undefined) => {
    if (!file) return;
    let parsed: unknown;
    try {
      parsed = JSON.parse(await file.text());
    } catch {
      toast.error(t("reports.cveFeedInvalid"));
      return;
    }
    replaceFeed.mutate(parsed);
    if (inputRef.current) inputRef.current.value = "";
  };

  const startAdd = () => {
    setEditingId(null);
    setDraft(emptyDraft());
    setAdding(true);
  };

  const startEdit = (entry: CveFeedEntry) => {
    setAdding(false);
    setEditingId(entry.id);
    setDraft(draftFromEntry(entry));
  };

  const cancelEdit = () => {
    setAdding(false);
    setEditingId(null);
    setDraft(emptyDraft());
  };

  const submitDraft = () => {
    const payload = draftPayload(draft);
    if (payload === "bad-id") {
      toast.error(t("reports.cveFeedBadId"));
      return;
    }
    if (payload === "need-target") {
      toast.error(t("reports.cveFeedNeedTarget"));
      return;
    }
    saveEntry.mutate(payload);
  };

  const removeEntry = async (entry: CveFeedEntry) => {
    const ok = await confirm({
      title: t("reports.cveFeedDeleteConfirmTitle"),
      message: t("reports.cveFeedDeleteConfirm", { cve: entry.cve_id }),
      confirmLabel: t("common.delete"),
      variant: "danger",
    });
    if (ok) deleteEntry.mutate(entry.id);
  };

  return (
    <Panel
      title={t("reports.cveFeedTitle")}
      toolbar={
        <div className="pf-cve-feed__actions">
          <Button variant="secondary" className="pf-btn--sm" disabled={busy || adding} onClick={startAdd}>
            {t("reports.cveFeedAdd")}
          </Button>
          <label className="pf-btn pf-btn--secondary pf-btn--sm">
            {t("reports.cveFeedReplace")}
            <input
              ref={inputRef}
              className="pf-cve-feed__file"
              type="file"
              accept="application/json,.json"
              aria-label={t("reports.cveFeedReplace")}
              disabled={busy}
              onChange={(event) => {
                void onFile(event.target.files?.[0]);
              }}
            />
          </label>
          {loaded ? (
            <Button variant="secondary" className="pf-btn--sm" disabled={busy} onClick={() => clearFeed.mutate()}>
              {t("reports.cveFeedClear")}
            </Button>
          ) : null}
        </div>
      }
    >
      <div className="pf-cve-feed">
        <div className="pf-cve-feed__stats" aria-label={t("reports.cveFeedTitle")}>
          <div className="pf-cve-feed__stat pf-cve-feed__stat--total">
            <div className="pf-cve-feed__stat-value">{stats.total}</div>
            <div className="pf-cve-feed__stat-label">{t("reports.cveFeedStatReferences")}</div>
            <div className="pf-cve-feed__stat-sub">
              {loaded && importedAt
                ? t("reports.cveFeedImported", { when: importedAt })
                : t("reports.cveFeedEmpty")}
            </div>
          </div>
          <div className="pf-cve-feed__stat">
            <div className="pf-cve-feed__stat-value">{stats.cves}</div>
            <div className="pf-cve-feed__stat-label">{t("reports.cveFeedStatCves")}</div>
          </div>
          <div className="pf-cve-feed__stat pf-cve-feed__stat--rule">
            <div className="pf-cve-feed__stat-value">{stats.byRule}</div>
            <div className="pf-cve-feed__stat-label">{t("reports.cveFeedStatRule")}</div>
          </div>
          <div className="pf-cve-feed__stat pf-cve-feed__stat--profile">
            <div className="pf-cve-feed__stat-value">{stats.byProfile}</div>
            <div className="pf-cve-feed__stat-label">{t("reports.cveFeedStatProfile")}</div>
          </div>
          <div className="pf-cve-feed__stat pf-cve-feed__stat--both">
            <div className="pf-cve-feed__stat-value">{stats.both}</div>
            <div className="pf-cve-feed__stat-label">{t("reports.cveFeedStatBoth")}</div>
          </div>
        </div>
        {adding ? (
          <EntryForm
            draft={draft}
            busy={busy}
            profiles={profilesForPick}
            rules={rulesForPick}
            rulesLoading={rulesLoading}
            onChange={setDraft}
            onSave={submitDraft}
            onCancel={cancelEdit}
          />
        ) : null}
        {entries.length > 0 ? (
          <div className="pf-cve-feed__table-wrap">
            <table className="pf-table pf-cve-feed__table">
              <thead>
                <tr>
                  <th scope="col">CVE</th>
                  <th scope="col">{t("reports.cveFeedRule")}</th>
                  <th scope="col">{t("reports.cveFeedProfile")}</th>
                  <th scope="col">{t("reports.cveFeedSummary")}</th>
                  <th scope="col">
                    <span className="pf-sr-only">{t("common.actions")}</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {entries.map((entry) =>
                  editingId === entry.id ? (
                    <tr key={entry.id}>
                      <td colSpan={5}>
                        <EntryForm
                          draft={draft}
                          busy={busy}
                          profiles={profilesForPick}
                          rules={rulesForPick}
                          rulesLoading={rulesLoading}
                          onChange={setDraft}
                          onSave={submitDraft}
                          onCancel={cancelEdit}
                        />
                      </td>
                    </tr>
                  ) : (
                    <FeedRow
                      key={entry.id}
                      entry={entry}
                      busy={busy}
                      onEdit={() => startEdit(entry)}
                      onDelete={() => void removeEntry(entry)}
                    />
                  )
                )}
              </tbody>
            </table>
          </div>
        ) : null}
      </div>
    </Panel>
  );
}

function ChoiceField({
  id,
  label,
  value,
  placeholder,
  pickLabel,
  choices,
  disabled,
  onChange,
}: {
  id: string;
  label: string;
  value: string;
  placeholder: string;
  pickLabel: string;
  choices: Choice[];
  disabled: boolean;
  onChange: (value: string) => void;
}) {
  const known = choices.some((choice) => choice.value === value);
  return (
    <div className="pf-form__group">
      <label htmlFor={id}>{label}</label>
      <div className="pf-cve-feed__combo">
        <input
          id={id}
          className="pf-input"
          value={value}
          placeholder={placeholder}
          disabled={disabled}
          onChange={(event) => onChange(event.target.value)}
        />
        <select
          className="pf-select"
          aria-label={pickLabel}
          value={known ? value : ""}
          disabled={disabled || choices.length === 0}
          onChange={(event) => {
            if (event.target.value) onChange(event.target.value);
          }}
        >
          <option value="">{pickLabel}</option>
          {choices.map((choice) => (
            <option key={choice.value} value={choice.value}>
              {choice.label}
            </option>
          ))}
        </select>
      </div>
    </div>
  );
}

function EntryForm({
  draft,
  busy,
  profiles,
  rules,
  rulesLoading,
  onChange,
  onSave,
  onCancel,
}: {
  draft: Draft;
  busy: boolean;
  profiles: Choice[];
  rules: Choice[];
  rulesLoading: boolean;
  onChange: (next: Draft) => void;
  onSave: () => void;
  onCancel: () => void;
}) {
  const { t } = useTranslation();
  return (
    <form
      className="pf-cve-feed__form"
      onSubmit={(event) => {
        event.preventDefault();
        onSave();
      }}
    >
      <div className="pf-form__group">
        <label htmlFor="cve-feed-id">CVE</label>
        <input
          id="cve-feed-id"
          className="pf-input"
          value={draft.cve_id}
          placeholder="CVE-2024-1234"
          disabled={busy}
          onChange={(event) => onChange({ ...draft, cve_id: event.target.value })}
        />
      </div>
      <ChoiceField
        id="cve-feed-rule"
        label={t("reports.cveFeedRule")}
        value={draft.requirement_id}
        placeholder="RULE1"
        pickLabel={rulesLoading ? t("common.loading") : t("reports.cveFeedPickRule")}
        choices={rules}
        disabled={busy}
        onChange={(requirement_id) => onChange({ ...draft, requirement_id })}
      />
      <ChoiceField
        id="cve-feed-profile"
        label={t("reports.cveFeedProfile")}
        value={draft.profile_name}
        placeholder="Ubuntu 22.04"
        pickLabel={t("reports.cveFeedPickProfile")}
        choices={profiles}
        disabled={busy}
        onChange={(profile_name) => onChange({ ...draft, profile_name })}
      />
      <div className="pf-form__group">
        <label htmlFor="cve-feed-note">{t("reports.cveFeedSummary")}</label>
        <input
          id="cve-feed-note"
          className="pf-input"
          value={draft.summary}
          disabled={busy}
          onChange={(event) => onChange({ ...draft, summary: event.target.value })}
        />
      </div>
      <div className="pf-cve-feed__form-actions">
        <Button type="submit" className="pf-btn--sm" disabled={busy} loading={busy}>
          {t("common.save")}
        </Button>
        <Button type="button" variant="secondary" className="pf-btn--sm" disabled={busy} onClick={onCancel}>
          {t("common.cancel")}
        </Button>
      </div>
      <p className="pf-cve-feed__hint">{t("reports.cveFeedNeedTarget")}</p>
    </form>
  );
}

function FeedRow({
  entry,
  busy,
  onEdit,
  onDelete,
}: {
  entry: CveFeedEntry;
  busy: boolean;
  onEdit: () => void;
  onDelete: () => void;
}) {
  const { t } = useTranslation();
  const rule = entry.requirement_id.trim() || t("reports.cveFeedAnyRule");
  const profile = entry.profile_name.trim() || t("reports.cveFeedAnyProfile");
  return (
    <tr>
      <td className="pf-table__mono">{entry.cve_id}</td>
      <td className={entry.requirement_id.trim() ? undefined : "pf-cve-feed__any"}>{rule}</td>
      <td className={entry.profile_name.trim() ? undefined : "pf-cve-feed__any"}>{profile}</td>
      <td>{entry.summary?.trim() || t("common.dash")}</td>
      <td className="pf-cve-feed__row-actions">
        <div className="pf-table__actions">
          <Button variant="secondary" className="pf-btn--sm" disabled={busy} onClick={onEdit}>
            {t("common.edit")}
          </Button>
          <Button variant="danger-secondary" className="pf-btn--sm" disabled={busy} onClick={onDelete}>
            {t("common.delete")}
          </Button>
        </div>
      </td>
    </tr>
  );
}
