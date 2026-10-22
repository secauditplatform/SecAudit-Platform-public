const API_BASE = import.meta.env.VITE_API_URL
  ? `${import.meta.env.VITE_API_URL}/api/v1`
  : "/api/v1";

let authToken: string | null = null;
let authRefreshHandler: (() => Promise<boolean>) | null = null;
let refreshInFlight: Promise<boolean> | null = null;

export function setAuthToken(token: string | null) {
  authToken = token;
}

export function setAuthRefreshHandler(handler: (() => Promise<boolean>) | null) {
  authRefreshHandler = handler;
}

async function refreshAuthOnce(): Promise<boolean> {
  if (!authRefreshHandler) return false;
  if (!refreshInFlight) {
    refreshInFlight = authRefreshHandler().finally(() => {
      refreshInFlight = null;
    });
  }
  return refreshInFlight;
}

async function errorMessageFromResponse(response: Response): Promise<string> {
  const detail = await response.text();
  let message = detail || `HTTP ${response.status}`;
  try {
    const parsed = JSON.parse(detail) as { detail?: unknown };
    if (typeof parsed.detail === "string") {
      message = parsed.detail;
    } else if (Array.isArray(parsed.detail)) {
      const parts = parsed.detail
        .map((item) => {
          if (!item || typeof item !== "object") return null;
          const entry = item as { msg?: string; loc?: unknown[] };
          const field = Array.isArray(entry.loc)
            ? entry.loc.filter((part) => part !== "body").join(".")
            : "";
          if (!entry.msg) return null;
          return field ? `${field}: ${entry.msg}` : entry.msg;
        })
        .filter((part): part is string => Boolean(part));
      if (parts.length > 0) {
        message = parts.join("; ");
      }
    } else if (parsed.detail && typeof parsed.detail === "object") {
      const obj = parsed.detail as { message?: string; code?: string };
      message = obj.message || obj.code || message;
    }
  } catch {
    if (detail.startsWith("Traceback")) {
      message = `HTTP ${response.status}: server error`;
    }
  }
  return message;
}

async function request<T>(path: string, options?: RequestInit, allowRefresh = true): Promise<T> {
  const isFormData = options?.body instanceof FormData;
  const headers = new Headers(options?.headers);
  if (!isFormData && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  if (authToken && !headers.has("Authorization")) {
    headers.set("Authorization", `Bearer ${authToken}`);
  }
  const response = await fetch(`${API_BASE}${path}`, { ...options, headers });
  if (
    response.status === 401 &&
    allowRefresh &&
    !path.startsWith("/auth/") &&
    (await refreshAuthOnce())
  ) {
    return request<T>(path, options, false);
  }
  if (!response.ok) {
    throw new Error(await errorMessageFromResponse(response));
  }
  if (response.status === 204) {
    return undefined as T;
  }
  return response.json() as Promise<T>;
}

export interface RemediationSuggestion {
  source_run_id: number;
  source_job_id: number;
  source_job_name: string;
  profile_id: number;
  profile_name: string;
  host_ids: number[];
  failed_count: number;
  failed_checks: Array<{
    host_id: number;
    rule_tech_name: string;
    status: string;
    message?: string | null;
  }>;
  remediation_scripts: Array<{
    id: number;
    name: string;
    execution_type: string;
  }>;
  suggested_name: string;
  default_execution_type: string;
  default_remediation_script_id: number | null;
}

export interface RemediationFromRunResult {
  remediation_job_id: number;
  remediation_run_id: number | null;
  baseline_run_id: number | null;
  source_run_id: number;
  source_job_id: number;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  offset: number;
  limit: number;
}

type ListParams = { offset?: number; limit?: number };

function listQuery(params?: ListParams): string {
  if (!params) return "";
  const query = new URLSearchParams();
  if (params.offset != null) query.set("offset", String(params.offset));
  if (params.limit != null) query.set("limit", String(params.limit));
  const qs = query.toString();
  return qs ? `?${qs}` : "";
}

function buildQuery(params?: Record<string, string | number | boolean | undefined | null>): string {
  if (!params) return "";
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === "") continue;
    query.set(key, String(value));
  }
  const qs = query.toString();
  return qs ? `?${qs}` : "";
}

async function downloadFile(path: string, filename: string, locale?: string): Promise<void> {
  const headers: Record<string, string> = {
    ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}),
  };
  if (locale) {
    headers["Accept-Language"] = locale;
  }
  const response = await fetch(`${API_BASE}${path}`, { headers });
  if (!response.ok) {
    const detail = await response.text();
    throw new Error(detail || `HTTP ${response.status}`);
  }
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

export interface Category {
  id: number;
  name: string;
  slug: string;
  category_type: string;
  description?: string;
  parent_id?: number;
}

export interface Profile {
  id: number;
  profile_name: string;
  version: string;
  summary?: string;
  category_id?: number;
  category_name?: string;
  package_path?: string | null;
  source_format?: "custom" | "xccdf" | string;
  profile_family?: string | null;
  scap_profile_id?: string | null;
  profile_title?: string | null;
  benchmark_ref?: string | null;
  os_name?: string | null;
  os_version?: string | null;
  os_vendor?: string | null;
  package_version?: string | null;
  needs_update?: boolean;
  is_active: boolean;
  created_at?: string;
}

export interface ProfileDependencies {
  jobs: number;
  remediation_jobs: number;
  waivers: number;
  job_runs: number;
  check_results: number;
  remediation_runs: number;
  active_runs: number;
}

export interface ProfilesBulkActionResult {
  succeeded: number[];
  failed: Array<{
    profile_id: number;
    message: string;
    code?: string | null;
    dependencies?: ProfileDependencies | null;
  }>;
}

export interface ProfileSyncResult {
  profile: Profile;
  updated: boolean;
}

export interface ProfilesCatalogEntry {
  package_path: string;
  profile_name: string;
  version: string;
  summary?: string | null;
  profile_family: string;
  category_slug: string;
  benchmark_ref?: string | null;
  platform: string;
  os_name?: string | null;
  os_version?: string | null;
  os_vendor?: string | null;
  imported: boolean;
  profile_id?: number | null;
  imported_version?: string | null;
  is_latest?: boolean;
  update_available?: boolean;
}

export interface ProfilesCatalogSyncStatus {
  enabled: boolean;
  interval_seconds: number;
  update_existing: boolean;
  mount_path: string;
  mount_available: boolean;
  pending_imports: number;
  pending_updates: number;
  last_run_at?: string | null;
  last_run_skipped: boolean;
  last_run_skip_reason?: string | null;
  last_imported_count: number;
  last_updated_count: number;
  last_skipped_count: number;
  last_error_count: number;
}

export interface ScapProfilePreview {
  profile_id: string;
  title: string;
  description?: string;
  benchmark_title: string;
  profile_family: string;
}

export interface ProfilesBulkImportResult {
  imported: Profile[];
  skipped: string[];
  errors: Array<{ package_path: string; message: string }>;
}

export interface InterpreterRule {
  id: number;
  regex: string;
  extraction_type: string;
  tech_name: string;
}

export interface CheckScript {
  id: number;
  name: string;
  execution_type: string;
  script_file: string;
  script_kind?: "audit" | "remediation";
  description?: string | null;
  interpreter_rules: InterpreterRule[];
}

export interface ProfileDetail extends Profile {
  check_scripts: CheckScript[];
  remediation_scripts?: CheckScript[];
}

export interface ProfileRule {
  num: string | null;
  tech_name: string;
  requirement_id: string;
  title?: string | null;
  explanation?: string | null;
  impact?: string | null;
  scope?: string | null;
  check_script?: string | null;
  scap_rule_id?: string | null;
  criticality?: string | null;
}

export interface ProfileRuleUpdate {
  title?: string | null;
  explanation?: string | null;
  impact?: string | null;
  scope?: string | null;
}

export interface ProfileRuleChangelogEntry {
  id: string;
  at: string;
  actor?: string | null;
  requirement_id: string;
  profile_version_before?: string | null;
  profile_version_after?: string | null;
  changes: Record<string, { from?: string | null; to?: string | null }>;
}

export interface ProfileRuleUpdateResult {
  rule: ProfileRule;
  profile_version: string;
  changelog_entry: ProfileRuleChangelogEntry;
}

export interface CheckScriptContent {
  script_file: string;
  content: string;
}

export interface Credential {
  id: number;
  name: string;
  credential_type: string;
  username?: string;
  service_username?: string | null;
  snmp_priv_protocol?: string | null;
  has_service_secret?: boolean;
  description?: string;
  created_at: string;
}

export type UserRole = "admin" | "operator" | "auditor";

export interface PlatformUser {
  id: number;
  username: string;
  email: string;
  full_name?: string | null;
  role: UserRole;
  is_active: boolean;
  mfa_enabled?: boolean;
  created_at: string;
}

export type ApiKeyScope = "jobs:run" | "reports:read" | "inventory:scan";

export interface ApiKey {
  id: number;
  name: string;
  key_prefix: string;
  scopes: string[];
  created_by?: string | null;
  created_at: string;
  last_used_at?: string | null;
  expires_at?: string | null;
  revoked_at?: string | null;
  is_active: boolean;
}

export interface ApiKeyCreated extends ApiKey {
  secret: string;
}

export type NotificationChannelType = "email" | "webhook" | "slack" | "teams" | "telegram" | "siem";
export type NotificationEventType =
  | "run_failed"
  | "run_completed"
  | "run_stale"
  | "dispatch_failed"
  | "worker_heartbeat_stale"
  | "worker_heartbeat_recovered"
  | "audit_event"
  | "audit_failed";

export interface NotificationChannel {
  id: number;
  name: string;
  channel_type: NotificationChannelType;
  is_active: boolean;
  events: NotificationEventType[];
  config_json?: Record<string, unknown> | null;
  owner_sub?: string | null;
  has_secret: boolean;
  created_at: string;
  updated_at: string;
}

export interface NotificationTestResponse {
  sent: number;
  skipped: number;
  errors: string[];
}

export type ScheduledReportFormat = "html" | "pdf" | "both";
export type ScheduledReportDelivery = "email" | "s3";

export interface ScheduledReport {
  id: number;
  name: string;
  job_id: number;
  cron_expression: string;
  is_active: boolean;
  report_format: ScheduledReportFormat;
  delivery_type: ScheduledReportDelivery;
  config_json?: Record<string, unknown> | null;
  has_secret: boolean;
  last_delivered_at?: string | null;
  last_delivered_run_id?: number | null;
  created_at: string;
  updated_at: string;
}

export interface ScheduledReportDeliverResponse {
  delivered: boolean;
  reason?: string | null;
  run_id?: number | null;
  delivery_type?: string | null;
  attachments?: string[];
  locations?: string[];
  delivered_at?: string | null;
}

export type PlaybookKind = "user" | "compliance_template";

export interface Playbook {
  id: number;
  name: string;
  description?: string;
  content: string;
  scope?: OperationsScope;
  platform?: "linux" | "windows" | "network";
  kind?: PlaybookKind;
  version?: string;
  profile_id?: number | null;
  profile_name?: string | null;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface PlaybookChangelogEntry {
  id: string;
  at: string;
  actor?: string | null;
  playbook_version_before?: string | null;
  playbook_version_after?: string | null;
  changes: Record<string, { from?: string | null; to?: string | null }>;
}

export interface PlaybookContentUpdateResult {
  playbook: Playbook;
  playbook_version: string;
  changelog_entry: PlaybookChangelogEntry;
}

export interface HostLinkedCredential {
  id: number;
  name: string;
  credential_type: "ssh_password" | "ssh_key" | "winrm";
  username?: string | null;
}

export type HostCriticality = "low" | "medium" | "high" | "critical";

export interface HostCsvImportResult {
  apply: boolean;
  created: number;
  updated: number;
  unchanged: number;
  truncated: boolean;
  rejected: { row: number; reason: string }[];
}

export interface Host {
  id: number;
  name: string;
  hostname: string;
  port: number;
  os_type?: string;
  site?: string | null;
  environment?: string | null;
  criticality?: HostCriticality | null;
  credential_id?: number | null;
  credential_ids?: number[];
  linked_credentials?: HostLinkedCredential[];
  is_active: boolean;
  tags?: string[];
  owner_sub?: string | null;
  ssh_host_key_fingerprint?: string | null;
}

export interface AuditFlowCredential {
  id: number;
  label: string;
  credential_type: "ssh_password" | "ssh_key" | "winrm";
  username: string;
}

export interface AuditFlowHost {
  id: number;
  ip_address: string;
  hostname?: string | null;
  platform?: string | null;
  os_guess?: string | null;
  open_ports: number[];
  credential_id?: number | null;
  credential_label?: string | null;
  profile_id?: number | null;
  profile_name?: string | null;
  confidence: number;
  alternatives: Array<{ profile_id: number; profile_name: string; confidence: number }>;
  extra_profiles?: Array<{ profile_id: number; profile_name: string; confidence: number; selected?: boolean }>;
  extra_checks?: Array<{
    profile_id?: number;
    profile_name?: string;
    job_run_id?: number | null;
    job_status?: string | null;
    passed?: number;
    failed?: number;
    total_checks?: number;
    compliance_percent?: number;
  }>;
  check_summary?: {
    job_run_id?: number;
    job_status?: string | null;
    passed?: number;
    failed?: number;
    total_checks?: number;
    compliance_percent?: number;
    error_message?: string | null;
  } | null;
  selected: boolean;
  skip_reason?: string | null;
  skip_detail?: string | null;
  job_run_id?: number | null;
  ephemeral_host_id?: number | null;
  inventory_reused?: boolean;
  ssh_host_key_fingerprint?: string | null;
  match_hints?: Array<{
    code: string;
    detail: string;
    profile_id?: number;
    confidence?: number;
  }>;
}

export interface AuditFlowRun {
  id: number;
  status: string;
  targets: string[];
  error_message?: string | null;
  hosts_found: number;
  save_to_inventory?: boolean;
  template_id?: number | null;
  started_at?: string | null;
  finished_at?: string | null;
  created_at: string;
  hosts: AuditFlowHost[];
  credentials?: AuditFlowCredential[];
  progress?: {
    phase?: string | null;
    target?: string | null;
    address?: string | null;
  } | null;
}

export interface AuditFlowTemplateCredential {
  label: string;
  credential_type: "ssh_password" | "ssh_key" | "winrm";
  username: string;
  service_username?: string | null;
  has_secret?: boolean;
  has_service_secret?: boolean;
}

export interface AuditFlowInventoryScope {
  tags: string[];
  site?: string | null;
}

export interface AuditFlowTemplate {
  id: number;
  name: string;
  description?: string | null;
  targets: string[];
  inventory_scope?: AuditFlowInventoryScope | null;
  credentials: AuditFlowTemplateCredential[];
  save_to_inventory: boolean;
  cron_expression?: string | null;
  is_scheduled: boolean;
  last_scheduled_at?: string | null;
  is_active: boolean;
  owner_sub?: string | null;
  created_at: string;
  updated_at: string;
}

export type AuditFlowInventoryChange = "appeared" | "disappeared" | "unchanged" | "changed";

export interface AuditFlowInventoryDriftHost {
  change: AuditFlowInventoryChange;
  ip_address: string;
  hostname?: string | null;
  ssh_host_key_fingerprint?: string | null;
  os_guess?: string | null;
  profile_id?: number | null;
  profile_name?: string | null;
  left_run_id?: number | null;
  right_run_id?: number | null;
  left_os_guess?: string | null;
  right_os_guess?: string | null;
  left_profile_name?: string | null;
  right_profile_name?: string | null;
}

export interface AuditFlowInventoryDriftSummary {
  left_run_id: number;
  right_run_id: number;
  left_hosts: number;
  right_hosts: number;
  appeared: number;
  disappeared: number;
  unchanged: number;
  changed: number;
}

export interface AuditFlowInventoryDriftReport {
  summary: AuditFlowInventoryDriftSummary;
  items: AuditFlowInventoryDriftHost[];
}

export interface DynamicHostFilter {
  tags: string[];
  active_only: boolean;
  search?: string | null;
  os_type?: string | null;
  site?: string | null;
  environment?: string | null;
  criticality?: HostCriticality | null;
}

export interface InventoryScan {
  id: number;
  target: string;
  status: string;
  started_at?: string;
  finished_at?: string;
  error_message?: string;
  hosts_found: number;
  hosts_created: number;
  nmap_flags?: string | null;
  method?: string;
  snmp_port?: number | null;
  created_at: string;
}

export interface InventoryScanResult {
  id: number;
  ip_address: string;
  resolved_hostname?: string;
  host_id?: number;
  open_ports: number[];
  ports_scanned?: boolean;
  platform_hint?: string | null;
  is_active: boolean;
  created_at: string;
}

export interface InventoryScanDetail extends InventoryScan {
  results: InventoryScanResult[];
}

export interface DirectorySource {
  id: number;
  name: string;
  server: string;
  port: number;
  use_ssl: boolean;
  start_tls: boolean;
  verify_tls: boolean;
  base_dn: string;
  bind_dn: string;
  enabled_only: boolean;
  map_ou_to_site: boolean;
  is_active: boolean;
  has_bind_password: boolean;
  created_at: string;
}

export interface DirectorySourceInput {
  name: string;
  server: string;
  port: number;
  use_ssl: boolean;
  start_tls: boolean;
  verify_tls: boolean;
  base_dn: string;
  bind_dn: string;
  bind_password?: string;
  enabled_only: boolean;
  map_ou_to_site: boolean;
  is_active: boolean;
}

export interface DirectorySync {
  id: number;
  source_id: number;
  status: string;
  hosts_found: number;
  hosts_created: number;
  hosts_updated: number;
  hosts_matched: number;
  error_message?: string | null;
  started_at?: string | null;
  finished_at?: string | null;
  created_at: string;
}

export type WebhookEventKey = "run_completed" | "run_failed" | "run_stale" | "dispatch_failed";

export type OperationsScope = "standard" | "network";
export type NetworkCheckMode = "remote" | "config_upload" | "both";
export type NetworkVendor =
  | "cisco_ios"
  | "cisco_nxos"
  | "cisco_asa"
  | "juniper_junos"
  | "arista_eos"
  | "huawei"
  | "h3c"
  | "fortinet"
  | "palo_alto"
  | "check_point"
  | "generic";

export interface Job {
  id: number;
  name: string;
  profile_id?: number | null;
  playbook_id?: number | null;
  execution_type?: "ssh" | "winrm" | "ansible" | "python" | null;
  scope?: OperationsScope;
  network_check_mode?: NetworkCheckMode | null;
  host_ids: number[];
  dynamic_filter?: DynamicHostFilter | null;
  is_scheduled: boolean;
  is_active: boolean;
  cron_expression?: string;
  owner_sub?: string | null;
  webhook_enabled?: boolean;
  webhook_events?: WebhookEventKey[];
  has_webhook_url?: boolean;
}

export interface JobTemplate {
  id: number;
  name: string;
  description?: string | null;
  profile_id?: number | null;
  playbook_id?: number | null;
  execution_type?: "ssh" | "winrm" | "ansible" | "python" | null;
  host_ids: number[];
  dynamic_filter?: DynamicHostFilter | null;
  is_scheduled: boolean;
  is_active: boolean;
  cron_expression?: string | null;
  profile_name?: string | null;
  playbook_name?: string | null;
  created_at: string;
  updated_at: string;
  owner_sub?: string | null;
}

export interface JobRun {
  id: number;
  job_id: number;
  status: string;
  started_at?: string;
  finished_at?: string;
  created_at?: string;
  error_message?: string;
  check_mode?: boolean;
}

export interface CveRef {
  cve_id: string;
  summary?: string | null;
  matched_by: "rule" | "package" | "rule_and_package";
}

export interface CveFeedEntry {
  id: number;
  cve_id: string;
  requirement_id: string;
  profile_name: string;
  summary?: string | null;
}

export interface CveFeedEntryInput {
  cve_id: string;
  requirement_id: string;
  profile_name: string;
  summary?: string | null;
}

export interface CveFeedStatus {
  loaded: boolean;
  entry_count: number;
  imported_at?: string | null;
  entries?: CveFeedEntry[];
}

export interface CheckResult {
  id: number;
  host_id: number;
  host_name?: string | null;
  rule_tech_name: string;
  status: string;
  message?: string;
  raw_output?: string;
  is_waived?: boolean;
  waiver_id?: number | null;
  cve_refs?: CveRef[];
}

export type WaiverStatus = "pending" | "approved" | "rejected" | "expired" | "revoked";

export interface ComplianceWaiver {
  id: number;
  profile_id: number;
  rule_tech_name: string;
  host_id?: number | null;
  job_id?: number | null;
  reason: string;
  change_ticket?: string | null;
  status: WaiverStatus;
  requested_by: string;
  approved_by?: string | null;
  approved_at?: string | null;
  rejected_by?: string | null;
  rejected_at?: string | null;
  rejection_reason?: string | null;
  expires_at?: string | null;
  is_active: boolean;
  owner_sub?: string | null;
  created_at: string;
  updated_at: string;
}

export interface WaiversBulkActionResult {
  succeeded: number[];
  failed: Array<{ waiver_id: number; message: string; code?: string | null }>;
}

export type PlaybookConnectionMode = "auto" | "ssh" | "paramiko" | "winrm";

export interface PlaybookTemplate {
  id: string;
  name: string;
  description: string;
  category: string;
  content: string;
  content_fast?: string | null;
}

export interface PlaybookRun {
  id: number;
  job_id: number;
  playbook_id?: number | null;
  playbook_name?: string | null;
  status: string;
  started_at?: string;
  finished_at?: string;
  error_message?: string;
  created_at: string;
  host_count: number;
  host_ids?: number[];
  check_mode?: boolean;
}

export interface JobRunDetail extends JobRun {
  check_results: CheckResult[];
}

export interface JobRunLogEntry {
  job_run_id: number;
  level: string;
  message: string;
  timestamp: string;
}

export interface AuditFlowLogEntry {
  audit_flow_run_id: number;
  level: string;
  message: string;
  timestamp: string;
}

export interface ReportSummary {
  job_run_id: number;
  total_checks: number;
  passed: number;
  failed: number;
  skipped: number;
  errors: number;
  waived?: number;
  compliance_percent: number;
  compliance_percent_raw?: number | null;
}

export type DriftChange = "improved" | "regressed" | "unchanged" | "new" | "removed";

export interface DriftItem {
  host_id: number;
  rule_tech_name: string;
  baseline_status: string | null;
  current_status: string | null;
  baseline_message?: string | null;
  current_message?: string | null;
  change: DriftChange;
}

export interface DriftSummary {
  current_run_id: number;
  baseline_run_id: number;
  improved: number;
  regressed: number;
  unchanged: number;
  new: number;
  removed: number;
  baseline_compliance_percent: number;
  current_compliance_percent: number;
  compliance_delta: number;
  baseline_failed?: number;
  closed_failed?: number;
  closed_fail_percent?: number | null;
}

export interface DriftReport {
  summary: DriftSummary;
  items: DriftItem[];
}

export interface DiffRow {
  key: string;
  host_id: number;
  rule_tech_name: string;
  left_status: string | null;
  right_status: string | null;
  left_message: string | null;
  right_message: string | null;
  change: DriftChange;
}

export interface DiffSummary {
  left_run_id: number;
  right_run_id: number;
  improved: number;
  regressed: number;
  unchanged: number;
  new: number;
  removed: number;
  left_compliance_percent: number;
  right_compliance_percent: number;
  compliance_delta: number;
  baseline_failed?: number;
  closed_failed?: number;
  closed_fail_percent?: number | null;
}

export interface DiffReport {
  summary: DiffSummary;
  items: DiffRow[];
}

export interface MultiRunCompareRunSummary {
  run_id: number;
  job_id: number;
  status: string;
  finished_at: string | null;
  compliance_percent: number;
  total_checks: number;
  passed: number;
  failed: number;
  skipped: number;
  errors: number;
}

export interface MultiRunCompareCell {
  run_id: number;
  status: string | null;
  message: string | null;
}

export interface MultiRunCompareRow {
  host_id: number;
  rule_tech_name: string;
  severity: string | null;
  cells: MultiRunCompareCell[];
}

export interface MultiRunCompareReport {
  job_id: number;
  run_ids: number[];
  runs: MultiRunCompareRunSummary[];
  rows: MultiRunCompareRow[];
}

export interface JobBaseline {
  baseline_run_id: number | null;
}

export interface ComplianceTimelinePoint {
  run_id: number;
  job_id: number;
  job_name: string;
  finished_at: string;
  compliance_percent: number;
  passed: number;
  failed: number;
  total_checks: number;
}

export interface HostCompliancePoint {
  host_id: number;
  host_name: string;
  compliance_percent: number;
  passed: number;
  failed: number;
  total_checks: number;
}

export interface ProfileCompliancePoint {
  profile_id: number;
  profile_name: string;
  job_count: number;
  avg_compliance_percent: number;
  latest_run_id: number | null;
}

export interface StatusCountPoint {
  key: string;
  count: number;
}

export interface DailyOpsPoint {
  day: string;
  runs: number;
  passed: number;
  failed: number;
  avg_compliance_percent: number;
}

export interface PlatformOpsPoint {
  platform: string;
  hosts: number;
  checks: number;
  avg_compliance_percent: number;
}

export interface RuleFailPoint {
  rule_tech_name: string;
  fail_count: number;
}

export interface ComplianceBandPoint {
  band: string;
  count: number;
}

export interface WeekdayHeatCell {
  weekday: number;
  week_index: number;
  week_start?: string | null;
  day?: string | null;
  avg_compliance_percent: number | null;
  runs: number;
}

export interface JobOpsPoint {
  job_id: number;
  job_name: string;
  runs: number;
  avg_compliance_percent: number;
  passed: number;
  failed: number;
  latest_run_id?: number | null;
}

export interface ComplianceOpsKpis {
  avg_compliance_percent: number | null;
  prev_avg_compliance_percent: number | null;
  completed_runs: number;
  failed_runs: number;
  running_runs: number;
  total_checks: number;
  passed: number;
  failed: number;
  skipped: number;
  errors: number;
  hosts: number;
  profiles: number;
  jobs?: number;
  waivers_approved: number;
  waivers_pending: number;
}

export interface ComplianceOpsOverview {
  days: number;
  kpis: ComplianceOpsKpis;
  outcome_mix: StatusCountPoint[];
  run_status_mix: StatusCountPoint[];
  bands: ComplianceBandPoint[];
  daily: DailyOpsPoint[];
  by_platform: PlatformOpsPoint[];
  by_job?: JobOpsPoint[];
  top_failing_rules: RuleFailPoint[];
  heatmap: WeekdayHeatCell[];
}

export interface RemediationJob {
  id: number;
  name: string;
  profile_id: number;
  remediation_script_id?: number | null;
  execution_type: "ssh" | "winrm" | "python" | "ansible";
  scope?: OperationsScope;
  dynamic_filter?: DynamicHostFilter | null;
  cron_expression?: string | null;
  is_scheduled: boolean;
  is_active: boolean;
  created_at: string;
  host_ids: number[];
  owner_sub?: string | null;
  webhook_enabled?: boolean;
  webhook_events?: WebhookEventKey[];
  has_webhook_url?: boolean;
}

export interface RemediationRun {
  id: number;
  remediation_job_id: number;
  status: string;
  started_at?: string;
  finished_at?: string;
  error_message?: string;
  created_at: string;
}

export interface RemediationResult {
  id: number;
  remediation_run_id: number;
  host_id: number;
  script_name: string;
  status: string;
  message?: string;
  raw_output?: string;
  created_at: string;
}

export interface RemediationRunDetail extends RemediationRun {
  results: RemediationResult[];
}

export interface AuditLog {
  id: number;
  created_at: string;
  actor_username: string;
  actor_roles?: string[] | null;
  action: string;
  resource_type: string;
  resource_id?: string | null;
  resource_name?: string | null;
  outcome: "success" | "failed";
  ip_address?: string | null;
  user_agent?: string | null;
  metadata_json?: Record<string, unknown> | null;
}

export interface AuditMetricPoint {
  label: string;
  count: number;
}

export interface AuditTimelinePoint {
  day: string;
  count: number;
}

export interface AuditOverview {
  total_events: number;
  period_days: number;
  events_over_time: AuditTimelinePoint[];
  top_actions: AuditMetricPoint[];
  top_actors: AuditMetricPoint[];
  outcomes: AuditMetricPoint[];
  resource_types: AuditMetricPoint[];
}

export type SearchResultType = "host" | "job" | "run" | "profile" | "remediation";

export interface SearchResultItem {
  type: SearchResultType;
  id: number;
  title: string;
  subtitle?: string | null;
  href: string;
  score?: number | null;
}

export interface SearchResponse {
  items: SearchResultItem[];
  query: string;
}

export type AuditMapService = {
  id: number | null;
  port: number;
  protocol: string;
  source: "connection" | "scan" | "manual" | string;
  confirmed: boolean;
  status: "pass" | "fail" | "error" | "unchecked" | string;
  coverage_reason: "unchecked" | "no_profile" | null;
};

export type AuditMapViewName = "network" | "service" | "platform" | "profile";

export type AuditMapNode = {
  host_id: number;
  name: string;
  hostname: string;
  ip: string | null;
  dns: string | null;
  port: number;
  os_type: string | null;
  site: string | null;
  environment: string | null;
  criticality: string | null;
  tags: string[];
  status: "pass" | "fail" | "error" | "unchecked";
  last_job_run_id: number | null;
  profile_id: number | null;
  profile_name: string | null;
  checks: { pass: number; fail: number; error: number } | null;
  x: number | null;
  y: number | null;
  subnet: string | null;
  services: AuditMapService[];
};

export type AuditMapPayload = {
  site: string | null;
  sites: string[];
  has_unassigned: boolean;
  truncated: boolean;
  groups: { subnet: string | null; nodes: AuditMapNode[] }[];
  views: Record<AuditMapViewName, { key: string | null; status: AuditMapNode["status"]; nodes: AuditMapNode[] }[]>;
  layouts: Partial<Record<AuditMapViewName, { host_id: number; x: number; y: number }[]>>;
  edges: {
    id: number;
    source_host_id: number;
    source_port: number;
    target_host_id: number;
    target_port: number;
  }[];
  profiles: { id: number; name: string }[];
};

export type AagProvider = "none" | "internal" | "external";

export interface AagStatus {
  enabled: boolean;
  provider: AagProvider;
  model_name?: string | null;
  reachable?: boolean | null;
  demo_mode: boolean;
}

export interface AagUsageModel {
  model_name: string;
  other: boolean;
  calls: number;
  failed: number;
  tokens: number;
  explain_calls: number;
  generate_calls: number;
}

export interface AagUsage {
  explain_total: number;
  explain_completed: number;
  explain_failed: number;
  explain_pending: number;
  generate_total: number;
  generate_completed: number;
  generate_failed: number;
  generate_pending: number;
  profiles_in_list: number;
  profiles_ready: number;
  calls_total: number;
  calls_failed: number;
  providers: number;
  explain_runs: number;
  tokens_total: number;
  tokens_explain: number;
  tokens_generate: number;
  duration_ms_avg: number;
  models: AagUsageModel[];
}

export interface AagConnection {
  id?: number | null;
  provider: AagProvider;
  internal_base_url?: string | null;
  external_base_url?: string | null;
  model_name?: string | null;
  has_external_key: boolean;
  enabled: boolean;
  selected?: boolean;
  timeout_seconds: number;
  max_tokens: number;
  updated_by?: string | null;
  updated_at?: string | null;
}

export interface AagConnectionInput {
  id?: number | null;
  provider: AagProvider;
  enabled?: boolean;
  internal_base_url?: string | null;
  external_base_url?: string | null;
  model_name?: string | null;
  external_api_key?: string | null;
  timeout_seconds?: number;
  max_tokens?: number;
}

export interface AagConnectionTestResult {
  ok: boolean;
  provider: AagProvider;
  host?: string | null;
  model_name?: string | null;
  message: string;
}

export interface AagCallLogEntry {
  id: number;
  provider: string;
  target_host?: string | null;
  model_name?: string | null;
  input_hash: string;
  kind?: string | null;
  draft_type?: string | null;
  outcome?: string | null;
  error_code?: string | null;
  duration_ms?: number | null;
  run_id?: number | null;
  in_perimeter?: boolean;
  token_count?: number | null;
  created_by?: string | null;
  created_at: string;
}

export type AagTaskKind = "explain" | "generate";

export interface AagTaskInput {
  kind: AagTaskKind;
  prompt?: string | null;
  run_id?: number | null;
  compare_run_id?: number | null;
  rule_tech_name?: string | null;
  host_id?: number | null;
  check_ids?: number[];
  profile_name?: string | null;
  profile_version?: string | null;
  target_kind?: "os" | "software";
  target_name?: string | null;
  target_vendor?: string | null;
  target_version?: string | null;
  overview?: string | null;
  purpose?: string | null;
  script_kind?: "sh" | "ps1" | "py";
}

export interface AagExplainCandidate {
  id: number;
  rule_tech_name: string;
  host_id: number;
  host_name?: string | null;
  os_type?: string | null;
  message?: string | null;
  rule_text?: string | null;
  rule_title?: string | null;
  has_remediation: boolean;
  status: string;
}

export interface AagParagraph {
  text: string;
  confirmed: boolean;
  is_fact: boolean;
}

export interface AagExplainSection {
  rule: string;
  host: string;
  status: string;
  what: string;
  checked: string;
  did: string;
  confirmed: boolean;
}

export interface AagPackageDraft {
  description: Record<string, unknown>;
  rules: Record<string, unknown>;
  script_name: string;
  script: string;
}

export interface AagArtifact {
  id: number;
  kind: AagTaskKind;
  status: "pending" | "completed" | "failed" | string;
  provider: string;
  model_name?: string | null;
  target_host?: string | null;
  in_perimeter: boolean;
  input_hash: string;
  prompt_redacted: string;
  response_text?: string | null;
  citations_json?: { run_id?: number; rule_tech_name?: string; host_id?: number } | null;
  meta_json?: {
    files?: AagPackageDraft | null;
    validation_errors?: string[];
    imported_profile_name?: string;
    profile_name?: string;
    checks?: { rule: string; host?: string; status: string; title?: string }[];
  } | null;
  paragraphs?: AagParagraph[];
  explain_sections?: AagExplainSection[];
  host_filter?: {
    site?: string;
    environment?: string;
    tag?: string;
    os_type?: string;
    criticality?: string;
    active_only?: boolean;
  } | null;
  error_message?: string | null;
  requested_by?: string | null;
  created_at: string;
  finished_at?: string | null;
}

export const api = {
  health: () => request<{ status: string; app_name: string }>("/health"),
  categories: () => request<Category[]>("/categories"),
  search: (params: { q: string; limit?: number; per_type?: number }) =>
    request<SearchResponse>(`/search${buildQuery(params)}`),
  profiles: (params?: {
    categoryId?: number;
    osName?: string;
    osVersion?: string;
    os?: string;
  }) =>
    request<Profile[]>(
      `/profiles${buildQuery({
        category_id: params?.categoryId,
        os_name: params?.osName,
        os_version: params?.osVersion,
        os: params?.os,
      })}`
    ),
  discoverProfiles: () => request<string[]>("/profiles/discover"),
  profilesCatalog: (family?: string, platform?: string) =>
    request<ProfilesCatalogEntry[]>(
      `/profiles/catalog${buildQuery({
        family: family || undefined,
        platform: platform || undefined,
      })}`
    ),
  streamProfilesCatalog: async function* (
    family?: string,
    platform?: string,
    signal?: AbortSignal
  ): AsyncGenerator<ProfilesCatalogEntry | { type: "done" }, void, unknown> {
    const response = await fetch(
      `${API_BASE}/profiles/catalog/stream${buildQuery({
        family: family || undefined,
        platform: platform || undefined,
      })}`,
      {
        headers: {
          ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}),
        },
        signal,
      }
    );
    if (!response.ok) {
      const detail = await response.text();
      throw new Error(detail || `HTTP ${response.status}`);
    }
    if (!response.body) {
      throw new Error("Streaming response body is empty");
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split("\n");
      buffer = lines.pop() ?? "";
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        const parsed = JSON.parse(trimmed) as ProfilesCatalogEntry | { type: "done" };
        yield parsed;
      }
    }

    const trailing = buffer.trim();
    if (trailing) {
      yield JSON.parse(trailing) as ProfilesCatalogEntry | { type: "done" };
    }
  },
  profilesCatalogSyncStatus: () =>
    request<ProfilesCatalogSyncStatus>("/profiles/catalog/sync-status"),
  previewCatalogRules: (packagePath: string, limit = 200) =>
    request<ProfileRule[]>(
      `/profiles/catalog/preview-rules${buildQuery({
        package_path: packagePath,
        limit,
      })}`
    ),
  importProfilesBulk: (packagePaths: string[], skipExisting = true, updateExisting = false) =>
    request<ProfilesBulkImportResult>("/profiles/import/bulk", {
      method: "POST",
      body: JSON.stringify({
        package_paths: packagePaths,
        skip_existing: skipExisting,
        update_existing: updateExisting,
      }),
    }),
  previewScapProfiles: (files: File[]) => {
    const formData = new FormData();
    for (const file of files) {
      const path = (file as File & { webkitRelativePath?: string }).webkitRelativePath;
      formData.append("files", file, path || file.name);
    }
    return request<ScapProfilePreview[]>("/profiles/import/preview-profiles", {
      method: "POST",
      body: formData,
    });
  },
  importProfile: (packagePath: string, categoryId?: number) => {
    const params = new URLSearchParams({ package_path: packagePath });
    if (categoryId != null) params.set("category_id", String(categoryId));
    return request<Profile>(`/profiles/import?${params.toString()}`, { method: "POST" });
  },
  importProfilePackage: (
    files: File[],
    categoryId?: number,
    scapProfileId?: string,
    compliancePlaybook?: File | null
  ) => {
    const formData = new FormData();
    for (const file of files) {
      const path = (file as File & { webkitRelativePath?: string }).webkitRelativePath;
      formData.append("files", file, path || file.name);
    }
    if (compliancePlaybook) {
      formData.append("compliance_playbook", compliancePlaybook, compliancePlaybook.name);
    }
    const params = new URLSearchParams();
    if (categoryId != null) params.set("category_id", String(categoryId));
    if (scapProfileId) params.set("scap_profile_id", scapProfileId);
    const query = params.toString() ? `?${params.toString()}` : "";
    return request<Profile>(`/profiles/import/upload${query}`, {
      method: "POST",
      body: formData,
    });
  },
  getProfile: (id: number) => request<ProfileDetail>(`/profiles/${id}`),
  getProfileRules: (id: number) => request<ProfileRule[]>(`/profiles/${id}/rules`),
  getProfileRuleChangelog: (id: number, limit = 100) =>
    request<ProfileRuleChangelogEntry[]>(`/profiles/${id}/rules/changelog${buildQuery({ limit })}`),
  updateProfileRule: (id: number, requirementId: string, data: ProfileRuleUpdate) =>
    request<ProfileRuleUpdateResult>(
      `/profiles/${id}/rules/${encodeURIComponent(requirementId)}`,
      {
        method: "PATCH",
        body: JSON.stringify(data),
      }
    ),
  getCheckScriptContent: (profileId: number, scriptId: number) =>
    request<CheckScriptContent>(`/profiles/${profileId}/scripts/${scriptId}/content`),
  updateCheckScriptContent: (profileId: number, scriptId: number, content: string) =>
    request<CheckScriptContent>(`/profiles/${profileId}/scripts/${scriptId}/content`, {
      method: "PUT",
      body: JSON.stringify({ content }),
    }),
  deleteProfile: (id: number, options?: { cascade?: boolean }) => {
    const query = options?.cascade ? "?cascade=true" : "";
    return request<void>(`/profiles/${id}${query}`, { method: "DELETE" });
  },
  getProfileDependencies: (id: number) =>
    request<ProfileDependencies>(`/profiles/${id}/dependencies`),
  syncProfile: (id: number) =>
    request<ProfileSyncResult>(`/profiles/${id}/sync`, { method: "POST" }),
  bulkEnableProfiles: (profileIds: number[]) =>
    request<ProfilesBulkActionResult>("/profiles/bulk/enable", {
      method: "POST",
      body: JSON.stringify({ profile_ids: profileIds }),
    }),
  bulkDisableProfiles: (profileIds: number[]) =>
    request<ProfilesBulkActionResult>("/profiles/bulk/disable", {
      method: "POST",
      body: JSON.stringify({ profile_ids: profileIds }),
    }),
  bulkDeleteProfiles: (profileIds: number[], options?: { cascade?: boolean }) =>
    request<ProfilesBulkActionResult>("/profiles/bulk/delete", {
      method: "POST",
      body: JSON.stringify({ profile_ids: profileIds, cascade: Boolean(options?.cascade) }),
    }),
  bulkSyncProfiles: (profileIds: number[]) =>
    request<ProfilesBulkActionResult>("/profiles/bulk/sync", {
      method: "POST",
      body: JSON.stringify({ profile_ids: profileIds }),
    }),
  credentials: () => request<Credential[]>("/credentials"),
  createCredential: (data: {
    name: string;
    credential_type: string;
    username?: string;
    secret: string;
    key_passphrase?: string;
    service_username?: string;
    service_secret?: string;
    snmp_priv_protocol?: string | null;
    description?: string;
  }) => request<Credential>("/credentials", { method: "POST", body: JSON.stringify(data) }),
  deleteCredential: (id: number) => request<void>(`/credentials/${id}`, { method: "DELETE" }),
  updateCredential: (
    id: number,
    data: {
      name?: string;
      credential_type?: string;
      username?: string;
      secret?: string;
      key_passphrase?: string;
      service_username?: string;
      service_secret?: string;
      snmp_priv_protocol?: string | null;
      description?: string;
    }
  ) => request<Credential>(`/credentials/${id}`, { method: "PATCH", body: JSON.stringify(data) }),
  users: () => request<PlatformUser[]>("/users"),
  createUser: (data: {
    username: string;
    email: string;
    full_name?: string;
    role: UserRole;
    password: string;
  }) => request<PlatformUser>("/users", { method: "POST", body: JSON.stringify(data) }),
  updateUser: (
    id: number,
    data: {
      username?: string;
      email?: string;
      full_name?: string | null;
      role?: UserRole;
      is_active?: boolean;
      password?: string;
    }
  ) => request<PlatformUser>(`/users/${id}`, { method: "PATCH", body: JSON.stringify(data) }),
  deleteUser: (id: number) => request<void>(`/users/${id}`, { method: "DELETE" }),
  apiKeys: () => request<ApiKey[]>("/api-keys"),
  createApiKey: (data: {
    name: string;
    scopes: ApiKeyScope[];
    expires_at?: string | null;
  }) => request<ApiKeyCreated>("/api-keys", { method: "POST", body: JSON.stringify(data) }),
  updateApiKey: (
    id: number,
    data: {
      name?: string;
      scopes?: ApiKeyScope[];
      expires_at?: string | null;
      is_active?: boolean;
    }
  ) => request<ApiKey>(`/api-keys/${id}`, { method: "PATCH", body: JSON.stringify(data) }),
  rotateApiKey: (id: number) =>
    request<ApiKeyCreated>(`/api-keys/${id}/rotate`, { method: "POST" }),
  revokeApiKey: (id: number) =>
    request<ApiKey>(`/api-keys/${id}/revoke`, { method: "POST" }),
  deleteApiKey: (id: number) => request<void>(`/api-keys/${id}`, { method: "DELETE" }),
  notificationChannels: () => request<NotificationChannel[]>("/notifications"),
  createNotificationChannel: (data: {
    name: string;
    channel_type: NotificationChannelType;
    is_active?: boolean;
    events: NotificationEventType[];
    config_json?: Record<string, unknown> | null;
    secret?: string;
  }) => request<NotificationChannel>("/notifications", { method: "POST", body: JSON.stringify(data) }),
  updateNotificationChannel: (
    id: number,
    data: {
      name?: string;
      channel_type?: NotificationChannelType;
      is_active?: boolean;
      events?: NotificationEventType[];
      config_json?: Record<string, unknown> | null;
      secret?: string;
    }
  ) => request<NotificationChannel>(`/notifications/${id}`, { method: "PATCH", body: JSON.stringify(data) }),
  deleteNotificationChannel: (id: number) => request<void>(`/notifications/${id}`, { method: "DELETE" }),
  testNotificationChannel: (id: number) =>
    request<NotificationTestResponse>(`/notifications/${id}/test`, { method: "POST" }),
  scheduledReports: () => request<ScheduledReport[]>("/scheduled-reports"),
  createScheduledReport: (data: {
    name: string;
    job_id: number;
    cron_expression: string;
    is_active?: boolean;
    report_format?: ScheduledReportFormat;
    delivery_type: ScheduledReportDelivery;
    config_json?: Record<string, unknown> | null;
    secret?: string;
  }) => request<ScheduledReport>("/scheduled-reports", { method: "POST", body: JSON.stringify(data) }),
  updateScheduledReport: (
    id: number,
    data: {
      name?: string;
      job_id?: number;
      cron_expression?: string;
      is_active?: boolean;
      report_format?: ScheduledReportFormat;
      delivery_type?: ScheduledReportDelivery;
      config_json?: Record<string, unknown> | null;
      secret?: string;
    }
  ) => request<ScheduledReport>(`/scheduled-reports/${id}`, { method: "PATCH", body: JSON.stringify(data) }),
  deleteScheduledReport: (id: number) => request<void>(`/scheduled-reports/${id}`, { method: "DELETE" }),
  deliverScheduledReport: (id: number, runId?: number) =>
    request<ScheduledReportDeliverResponse>(
      `/scheduled-reports/${id}/deliver${runId != null ? `?run_id=${runId}` : ""}`,
      { method: "POST" }
    ),
  localLogin: (username: string, password: string) =>
    request<{
      access_token?: string | null;
      refresh_token?: string | null;
      token_type: string;
      username: string;
      expires_in?: number | null;
      mfa_required?: boolean;
      mfa_token?: string | null;
    }>("/auth/local", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    }),
  verifyMfa: (mfaToken: string, code: string) =>
    request<{
      access_token: string;
      refresh_token: string;
      token_type: string;
      username: string;
      expires_in: number;
      mfa_required?: boolean;
    }>("/auth/mfa/verify", {
      method: "POST",
      body: JSON.stringify({ mfa_token: mfaToken, code }),
    }),
  mfaStatus: () =>
    request<{ enabled: boolean; recovery_codes_remaining: number }>("/auth/mfa/status"),
  mfaSetup: () => request<{ secret: string; otpauth_uri: string }>("/auth/mfa/setup", { method: "POST" }),
  mfaConfirm: (code: string) =>
    request<{ enabled: boolean; recovery_codes: string[] }>("/auth/mfa/confirm", {
      method: "POST",
      body: JSON.stringify({ code }),
    }),
  mfaDisable: (password: string, code: string) =>
    request<void>("/auth/mfa/disable", {
      method: "POST",
      body: JSON.stringify({ password, code }),
    }),
  resetUserMfa: (id: number) =>
    request<PlatformUser>(`/users/${id}/mfa/reset`, { method: "POST" }),
  scanLimits: () =>
    request<{ max_cidr_prefix_len: number; max_targets: number }>("/inventory/scan-limits"),
  demoLogin: () =>
    request<{
      access_token: string;
      refresh_token: string;
      token_type: string;
      username: string;
      expires_in: number;
    }>("/auth/demo", {
      method: "POST",
      body: "{}",
    }),
  demoLogout: () => request<void>("/auth/demo/logout", { method: "POST" }),
  logout: () => request<void>("/auth/logout", { method: "POST" }),
  refreshLocalToken: (refresh_token: string) =>
    request<{
      access_token: string;
      refresh_token: string;
      token_type: string;
      expires_in: number;
    }>("/auth/refresh", {
      method: "POST",
      body: JSON.stringify({ refresh_token }),
    }),
  playbooks: (
    scope?: OperationsScope,
    platform?: "linux" | "windows" | "network",
    kind?: PlaybookKind
  ) => request<Playbook[]>(`/playbooks${buildQuery({ scope, platform, kind })}`),
  playbookTemplates: (scope?: OperationsScope) =>
    request<PlaybookTemplate[]>(`/playbooks/templates${scope ? buildQuery({ scope }) : ""}`),
  playbookRuns: (params?: {
    playbookId?: number;
    limit?: number;
    scope?: OperationsScope;
    platform?: "linux" | "windows" | "network";
  }) =>
    request<PlaybookRun[]>(
      `/playbooks/runs${buildQuery({
        playbook_id: params?.playbookId,
        limit: params?.limit,
        scope: params?.scope,
        platform: params?.platform,
      })}`
    ),
  runPlaybook: (
    playbookId: number,
    hostIds: number[],
    connectionMode: PlaybookConnectionMode = "auto",
    checkMode = false
  ) =>
    request<PlaybookRun>(`/playbooks/${playbookId}/run`, {
      method: "POST",
      body: JSON.stringify({
        host_ids: hostIds,
        connection_mode: connectionMode,
        check_mode: checkMode,
      }),
    }),
  createPlaybook: (data: {
    name: string;
    description?: string;
    content: string;
    scope?: OperationsScope;
    platform?: "linux" | "windows" | "network";
  }) => request<Playbook>("/playbooks", { method: "POST", body: JSON.stringify(data) }),
  updatePlaybook: (
    id: number,
    data: Partial<{
      name: string;
      description: string;
      content: string;
      platform: "linux" | "windows" | "network";
    }>
  ) => request<Playbook>(`/playbooks/${id}`, { method: "PUT", body: JSON.stringify(data) }),
  updatePlaybookContent: (id: number, content: string) =>
    request<PlaybookContentUpdateResult>(`/playbooks/${id}/content`, {
      method: "PATCH",
      body: JSON.stringify({ content }),
    }),
  getPlaybookChangelog: (id: number, limit = 100) =>
    request<PlaybookChangelogEntry[]>(`/playbooks/${id}/changelog${buildQuery({ limit })}`),
  validatePlaybook: (data: { name: string; description?: string; content: string }) =>
    request<{ valid: boolean; message: string }>("/playbooks/validate", {
      method: "POST",
      body: JSON.stringify(data),
    }),
  deletePlaybook: (id: number) => request<void>(`/playbooks/${id}`, { method: "DELETE" }),
  hosts: (
    params?: ListParams & {
      site?: string;
      environment?: string;
      tag?: string;
      os_type?: string;
      criticality?: string;
      active_only?: boolean;
    },
  ) => request<PaginatedResponse<Host>>(`/hosts${buildQuery(params)}`),
  getHost: (id: number) => request<Host>(`/hosts/${id}`),
  hostTags: () => request<{ id: number; name: string; created_at: string }[]>("/hosts/tags"),
  setHostTags: (hostId: number, tagNames: string[]) =>
    request<Host>(`/hosts/${hostId}/tags`, { method: "PUT", body: JSON.stringify({ tag_names: tagNames }) }),
  importHostsCsv: (file: File, apply = false) => {
    const body = new FormData();
    body.append("file", file);
    return request<HostCsvImportResult>(
      `/hosts/import/csv${buildQuery({ apply: apply ? "true" : undefined })}`,
      { method: "POST", body }
    );
  },
  createHost: (data: Omit<Host, "id">) =>
    request<Host>("/hosts", { method: "POST", body: JSON.stringify(data) }),
  updateHost: (id: number, data: Partial<Omit<Host, "id">>) =>
    request<Host>(`/hosts/${id}`, { method: "PATCH", body: JSON.stringify(data) }),
  linkHostCredential: (hostId: number, credentialId: number) =>
    request<Host>(`/hosts/${hostId}/credentials`, {
      method: "POST",
      body: JSON.stringify({ credential_id: credentialId }),
    }),
  unlinkHostCredential: (hostId: number, credentialId: number) =>
    request<Host>(`/hosts/${hostId}/credentials/${credentialId}`, { method: "DELETE" }),
  deleteHost: (id: number) => request<void>(`/hosts/${id}`, { method: "DELETE" }),
  scanHostSshFingerprint: (id: number) =>
    request<{ fingerprint: string; saved: boolean }>(`/hosts/${id}/scan-ssh-fingerprint`, {
      method: "POST",
    }),
  bulkDeleteHosts: (hostIds: number[]) =>
    request<{ deleted: number[]; conflicts: { host_id: number; detail: string }[] }>(
      "/hosts/bulk-delete",
      { method: "POST", body: JSON.stringify({ host_ids: hostIds }) }
    ),
  bulkClassifyHosts: (data: {
    host_ids: number[];
    site?: string;
    environment?: string;
    criticality?: HostCriticality;
  }) =>
    request<{ updated: number[]; skipped: { host_id: number; detail: string }[] }>(
      "/hosts/bulk-classify",
      { method: "POST", body: JSON.stringify(data) }
    ),
  auditMap: (params?: { site?: string; environment?: string; criticality?: string; tag?: string; profile?: string }) =>
    request<AuditMapPayload>(`/audit-map${buildQuery(params)}`),
  confirmAuditMapService: (hostId: number, port: number) =>
    request<AuditMapService>("/audit-map/services", {
      method: "POST",
      body: JSON.stringify({ host_id: hostId, port }),
    }),
  deleteAuditMapService: (serviceId: number) =>
    request<void>(`/audit-map/services/${serviceId}`, { method: "DELETE" }),
  createAuditMapEdge: (data: {
    source_host_id: number;
    source_port: number;
    target_host_id: number;
    target_port: number;
  }) => request<AuditMapPayload["edges"][number]>("/audit-map/edges", { method: "POST", body: JSON.stringify(data) }),
  deleteAuditMapEdge: (edgeId: number) =>
    request<void>(`/audit-map/edges/${edgeId}`, { method: "DELETE" }),
  inventoryScans: () => request<InventoryScan[]>("/inventory/scans"),
  startInventoryScan: (data: {
    target: string;
    method?: "nmap" | "snmp";
    nmap_flags?: string;
    credential_id?: number;
    snmp_port?: number;
  }) =>
    request<InventoryScan>("/inventory/scans", { method: "POST", body: JSON.stringify(data) }),
  getInventoryScan: (scanId: number) => request<InventoryScanDetail>(`/inventory/scans/${scanId}`),
  deleteInventoryScan: (scanId: number) =>
    request<void>(`/inventory/scans/${scanId}`, { method: "DELETE" }),
  stopInventoryScan: (scanId: number) =>
    request<InventoryScan>(`/inventory/scans/${scanId}/stop`, { method: "POST" }),
  directorySources: () => request<DirectorySource[]>("/directory/sources"),
  createDirectorySource: (data: DirectorySourceInput) =>
    request<DirectorySource>("/directory/sources", { method: "POST", body: JSON.stringify(data) }),
  updateDirectorySource: (id: number, data: Partial<DirectorySourceInput>) =>
    request<DirectorySource>(`/directory/sources/${id}`, { method: "PATCH", body: JSON.stringify(data) }),
  deleteDirectorySource: (id: number) =>
    request<void>(`/directory/sources/${id}`, { method: "DELETE" }),
  testDirectorySource: (data: {
    server: string;
    port: number;
    use_ssl: boolean;
    start_tls: boolean;
    verify_tls: boolean;
    base_dn: string;
    bind_dn: string;
    bind_password?: string;
    enabled_only: boolean;
    source_id?: number;
  }) =>
    request<{ computers: number; sample: string[]; truncated: boolean }>("/directory/sources/test", {
      method: "POST",
      body: JSON.stringify(data),
    }),
  directorySyncs: () => request<DirectorySync[]>("/directory/syncs"),
  startDirectorySync: (sourceId: number) =>
    request<DirectorySync>(`/directory/sources/${sourceId}/sync`, { method: "POST" }),
  jobs: (scope?: OperationsScope) =>
    request<Job[]>(`/jobs${scope ? buildQuery({ scope }) : ""}`),
  createJob: (data: {
    name: string;
    profile_id?: number;
    playbook_id?: number;
    execution_type?: "ssh" | "winrm" | "python" | "ansible";
    scope?: OperationsScope;
    network_check_mode?: NetworkCheckMode;
    host_ids: number[];
    dynamic_filter?: DynamicHostFilter | null;
    is_scheduled?: boolean;
    cron_expression?: string;
    webhook_enabled?: boolean;
    webhook_events?: WebhookEventKey[];
    webhook_url?: string;
  }) => request<Job>("/jobs", { method: "POST", body: JSON.stringify(data) }),
  updateJob: (
    id: number,
    data: {
      name?: string;
      profile_id?: number | null;
      playbook_id?: number | null;
      execution_type?: "ssh" | "winrm" | "python" | "ansible" | null;
      network_check_mode?: NetworkCheckMode;
      host_ids?: number[];
      dynamic_filter?: DynamicHostFilter | null;
      is_scheduled?: boolean;
      cron_expression?: string | null;
      webhook_enabled?: boolean;
      webhook_events?: WebhookEventKey[];
      webhook_url?: string;
      clear_webhook_url?: boolean;
    }
  ) => request<Job>(`/jobs/${id}`, { method: "PATCH", body: JSON.stringify(data) }),
  jobRuns: (params?: ListParams) =>
    request<PaginatedResponse<JobRun>>(`/jobs/runs${listQuery(params)}`),
  runJob: (jobId: number) => request<JobRun>(`/jobs/${jobId}/run`, { method: "POST" }),
  stopJobRun: (runId: number) => request<JobRun>(`/jobs/runs/${runId}/stop`, { method: "POST" }),
  deleteJobRun: (runId: number) => request<void>(`/jobs/runs/${runId}`, { method: "DELETE" }),
  deleteJob: (jobId: number) => request<void>(`/jobs/${jobId}`, { method: "DELETE" }),
  jobTemplates: () => request<JobTemplate[]>("/job-templates"),
  createJobTemplate: (data: {
    name: string;
    description?: string;
    profile_id?: number;
    playbook_id?: number;
    execution_type?: "ssh" | "winrm" | "python";
    host_ids?: number[];
    dynamic_filter?: DynamicHostFilter | null;
    is_scheduled?: boolean;
    cron_expression?: string;
    is_active?: boolean;
  }) => request<JobTemplate>("/job-templates", { method: "POST", body: JSON.stringify(data) }),
  updateJobTemplate: (
    id: number,
    data: {
      name?: string;
      description?: string | null;
      profile_id?: number | null;
      playbook_id?: number | null;
      execution_type?: "ssh" | "winrm" | "python" | null;
      host_ids?: number[];
      dynamic_filter?: DynamicHostFilter | null;
      is_scheduled?: boolean;
      cron_expression?: string | null;
      is_active?: boolean;
    }
  ) => request<JobTemplate>(`/job-templates/${id}`, { method: "PATCH", body: JSON.stringify(data) }),
  deleteJobTemplate: (id: number) => request<void>(`/job-templates/${id}`, { method: "DELETE" }),
  applyJobTemplate: (
    id: number,
    data?: { name?: string; host_ids?: number[]; dynamic_filter?: DynamicHostFilter | null; run_after_create?: boolean }
  ) => request<Job>(`/job-templates/${id}/apply`, { method: "POST", body: JSON.stringify(data ?? {}) }),
  getJobRun: (runId: number) => request<JobRunDetail>(`/jobs/runs/${runId}`),
  getJobRunLogs: (runId: number) => request<JobRunLogEntry[]>(`/ws/job-runs/${runId}/logs`),
  runSummary: (runId: number) => request<ReportSummary>(`/reports/runs/${runId}/summary`),
  getRemediationSuggestions: (runId: number) =>
    request<RemediationSuggestion>(`/reports/runs/${runId}/remediation-suggestions`),
  createRemediationFromRun: (data: {
    source_run_id: number;
    name?: string;
    remediation_script_id?: number;
    run_remediation?: boolean;
    set_baseline?: boolean;
  }) =>
    request<RemediationFromRunResult>("/remediations/from-run", {
      method: "POST",
      body: JSON.stringify(data),
    }),
  getRunDrift: (runId: number, baselineRunId: number) =>
    request<DriftReport>(`/reports/runs/${runId}/drift?baseline_run_id=${baselineRunId}`),
  getRunsDiff: (leftRunId: number, rightRunId: number) =>
    request<DiffReport>(`/reports/diff?left_run_id=${leftRunId}&right_run_id=${rightRunId}`),
  getRunsCompare: (runIds: number[]) =>
    request<MultiRunCompareReport>(
      `/reports/compare${buildQuery({ run_ids: runIds.join(",") })}`
    ),
  getJobBaseline: (jobId: number) => request<JobBaseline>(`/reports/jobs/${jobId}/baseline`),
  setJobBaseline: (jobId: number, runId: number) =>
    request<JobBaseline>(`/reports/jobs/${jobId}/baseline`, {
      method: "PUT",
      body: JSON.stringify({ run_id: runId }),
    }),
  clearJobBaseline: (jobId: number) =>
    request<void>(`/reports/jobs/${jobId}/baseline`, { method: "DELETE" }),
  complianceTimeline: (params?: {
    job_id?: number;
    profile_id?: number;
    days?: number;
    date_from?: string;
    date_to?: string;
    limit?: number;
  }) => {
    const query = new URLSearchParams();
    if (params?.job_id != null) query.set("job_id", String(params.job_id));
    if (params?.profile_id != null) query.set("profile_id", String(params.profile_id));
    if (params?.days != null) query.set("days", String(params.days));
    if (params?.date_from) query.set("date_from", params.date_from);
    if (params?.date_to) query.set("date_to", params.date_to);
    if (params?.limit != null) query.set("limit", String(params.limit));
    const qs = query.toString();
    return request<ComplianceTimelinePoint[]>(`/reports/trends/compliance${qs ? `?${qs}` : ""}`);
  },
  complianceByHost: (runId: number) =>
    request<HostCompliancePoint[]>(`/reports/trends/by-host?run_id=${runId}`),
  complianceByProfile: (params: { days?: number; date_from?: string; date_to?: string } = {}) => {
    const query = new URLSearchParams();
    if (params.days != null) query.set("days", String(params.days));
    if (params.date_from) query.set("date_from", params.date_from);
    if (params.date_to) query.set("date_to", params.date_to);
    const qs = query.toString();
    return request<ProfileCompliancePoint[]>(`/reports/trends/by-profile${qs ? `?${qs}` : ""}`);
  },
  complianceOperations: (params: { days?: number; date_from?: string; date_to?: string } = {}) => {
    const query = new URLSearchParams();
    if (params.days != null) query.set("days", String(params.days));
    if (params.date_from) query.set("date_from", params.date_from);
    if (params.date_to) query.set("date_to", params.date_to);
    const qs = query.toString();
    return request<ComplianceOpsOverview>(`/reports/trends/operations${qs ? `?${qs}` : ""}`);
  },
  downloadReportHtml: (runId: number, locale = "en") =>
    downloadFile(
      `/reports/runs/${runId}/report.html?locale=${encodeURIComponent(locale)}`,
      `report-${runId}.html`,
      locale
    ),
  downloadReportPdf: (runId: number, locale = "en") =>
    downloadFile(
      `/reports/runs/${runId}/report.pdf?locale=${encodeURIComponent(locale)}`,
      `report-${runId}.pdf`,
      locale
    ),
  cveFeedStatus: () => request<CveFeedStatus>("/cve-feed"),
  replaceCveFeed: (payload: unknown) =>
    request<CveFeedStatus>("/cve-feed", { method: "PUT", body: JSON.stringify(payload) }),
  clearCveFeed: () => request<CveFeedStatus>("/cve-feed", { method: "DELETE" }),
  createCveFeedEntry: (payload: CveFeedEntryInput) =>
    request<CveFeedStatus>("/cve-feed/entries", { method: "POST", body: JSON.stringify(payload) }),
  updateCveFeedEntry: (id: number, payload: CveFeedEntryInput) =>
    request<CveFeedStatus>(`/cve-feed/entries/${id}`, { method: "PATCH", body: JSON.stringify(payload) }),
  deleteCveFeedEntry: (id: number) =>
    request<CveFeedStatus>(`/cve-feed/entries/${id}`, { method: "DELETE" }),
  downloadReportCsv: (
    runId: number,
    filters?: { status?: string; severity?: string; host_id?: number | string; rule?: string }
  ) =>
    downloadFile(
      `/reports/runs/${runId}/report.csv${buildQuery(filters)}`,
      `report-${runId}.csv`
    ),
  downloadReportPack: (runId: number, locale = "en") =>
    downloadFile(
      `/reports/runs/${runId}/report.pack.zip?locale=${encodeURIComponent(locale)}`,
      `report-${runId}-pack.zip`,
      locale
    ),
  downloadRunsCompareCsv: (runIds: number[]) =>
    downloadFile(
      `/reports/compare.csv${buildQuery({ run_ids: runIds.join(",") })}`,
      `compare-${runIds.join("-")}.csv`
    ),
  remediations: (scope?: OperationsScope) =>
    request<RemediationJob[]>(`/remediations${scope ? buildQuery({ scope }) : ""}`),
  waivers: (params?: {
    profile_id?: number;
    host_id?: number;
    job_id?: number;
    status?: WaiverStatus;
    active_only?: boolean;
  }) =>
    request<ComplianceWaiver[]>(
      `/waivers${buildQuery({
        profile_id: params?.profile_id,
        host_id: params?.host_id,
        job_id: params?.job_id,
        status: params?.status,
        active_only:
          params?.active_only == null ? undefined : params.active_only ? "true" : "false",
      })}`
    ),
  createWaiver: (data: {
    profile_id: number;
    rule_tech_name: string;
    host_id?: number | null;
    job_id?: number | null;
    reason: string;
    change_ticket?: string | null;
    expires_at?: string | null;
    auto_approve?: boolean;
  }) => request<ComplianceWaiver>("/waivers", { method: "POST", body: JSON.stringify(data) }),
  approveWaiver: (id: number, changeTicket?: string | null) =>
    request<ComplianceWaiver>(`/waivers/${id}/approve`, {
      method: "POST",
      body: JSON.stringify({ change_ticket: changeTicket?.trim() || null }),
    }),
  rejectWaiver: (id: number, reason?: string) =>
    request<ComplianceWaiver>(`/waivers/${id}/reject`, {
      method: "POST",
      body: JSON.stringify({ reason: reason ?? null }),
    }),
  bulkApproveWaivers: (waiverIds: number[], changeTicket?: string | null) =>
    request<WaiversBulkActionResult>("/waivers/bulk/approve", {
      method: "POST",
      body: JSON.stringify({
        waiver_ids: waiverIds,
        change_ticket: changeTicket?.trim() || null,
      }),
    }),
  bulkRejectWaivers: (waiverIds: number[], reason?: string | null) =>
    request<WaiversBulkActionResult>("/waivers/bulk/reject", {
      method: "POST",
      body: JSON.stringify({
        waiver_ids: waiverIds,
        reason: reason?.trim() || null,
      }),
    }),
  revokeWaiver: (id: number) =>
    request<ComplianceWaiver>(`/waivers/${id}/revoke`, { method: "POST" }),
  deleteWaiver: (id: number) => request<void>(`/waivers/${id}`, { method: "DELETE" }),
  createRemediation: (data: {
    name: string;
    profile_id: number;
    remediation_script_id?: number;
    execution_type: "ssh" | "winrm" | "python" | "ansible";
    host_ids: number[];
    dynamic_filter?: DynamicHostFilter | null;
    is_scheduled?: boolean;
    cron_expression?: string;
    webhook_enabled?: boolean;
    webhook_events?: WebhookEventKey[];
    webhook_url?: string;
  }) => request<RemediationJob>("/remediations", { method: "POST", body: JSON.stringify(data) }),
  updateRemediation: (
    id: number,
    data: {
      name?: string;
      profile_id?: number;
      remediation_script_id?: number | null;
      execution_type?: "ssh" | "winrm" | "python" | "ansible";
      host_ids?: number[];
      dynamic_filter?: DynamicHostFilter | null;
      is_scheduled?: boolean;
      cron_expression?: string | null;
      webhook_enabled?: boolean;
      webhook_events?: WebhookEventKey[];
      webhook_url?: string;
      clear_webhook_url?: boolean;
    }
  ) => request<RemediationJob>(`/remediations/${id}`, { method: "PATCH", body: JSON.stringify(data) }),
  remediationRuns: (params?: ListParams) =>
    request<PaginatedResponse<RemediationRun>>(`/remediations/runs${listQuery(params)}`),
  runRemediation: (jobId: number) =>
    request<RemediationRun>(`/remediations/${jobId}/run`, { method: "POST" }),
  stopRemediationRun: (runId: number) =>
    request<RemediationRun>(`/remediations/runs/${runId}/stop`, { method: "POST" }),
  deleteRemediationRun: (runId: number) =>
    request<void>(`/remediations/runs/${runId}`, { method: "DELETE" }),
  deleteRemediation: (jobId: number) =>
    request<void>(`/remediations/${jobId}`, { method: "DELETE" }),
  getRemediationRun: (runId: number) =>
    request<RemediationRunDetail>(`/remediations/runs/${runId}`),
  auditLogs: (params?: {
    offset?: number;
    limit?: number;
    action?: string;
    resource_type?: string;
    actor_username?: string;
    outcome?: string;
    from?: string;
    to?: string;
  }) => request<PaginatedResponse<AuditLog>>(`/audit-logs${buildQuery(params)}`),
  auditOverview: (params?: { days?: number; top?: number }) =>
    request<AuditOverview>(`/audit-logs/overview${buildQuery(params)}`),
  listNetworkConfigs: (jobId: number) =>
    request<Array<{ id: number; job_id: number; host_id?: number | null; vendor: NetworkVendor; filename: string; created_at: string }>>(
      `/network/jobs/${jobId}/configs`
    ),
  uploadNetworkConfig: async (
    jobId: number,
    file: File,
    opts?: { hostId?: number; vendor?: NetworkVendor }
  ) => {
    const form = new FormData();
    form.append("file", file);
    if (opts?.hostId != null) form.append("host_id", String(opts.hostId));
    if (opts?.vendor) form.append("vendor", opts.vendor);
    const response = await fetch(`${API_BASE}/network/jobs/${jobId}/configs/upload`, {
      method: "POST",
      headers: authToken ? { Authorization: `Bearer ${authToken}` } : {},
      body: form,
    });
    if (!response.ok) {
      throw new Error(await response.text());
    }
    return response.json();
  },
  generateNetworkRemediationConfig: (
    runId: number,
    data: {
      vendor: NetworkVendor;
      host_id?: number;
      hostname?: string;
      commands?: string[];
      content?: string;
      filename?: string;
    }
  ) =>
    request<{ id: number; filename: string }>(`/network/remediations/runs/${runId}/configs/generate`, {
      method: "POST",
      body: JSON.stringify(data),
    }),
  downloadNetworkRemediationConfig: async (runId: number, configId: number, filename: string) => {
    await downloadFile(`/network/remediations/runs/${runId}/configs/${configId}/download`, filename);
  },
  listAuditFlowRuns: () => request<AuditFlowRun[]>("/audit-flow/runs"),
  startAuditFlow: (data: {
    targets: string[];
    credentials: Array<{
      label?: string;
      credential_type: "ssh_password" | "ssh_key" | "winrm";
      username: string;
      secret: string;
      key_passphrase?: string;
      service_username?: string;
      service_secret?: string;
    }>;
    save_to_inventory?: boolean;
  }) => request<AuditFlowRun>("/audit-flow/runs", { method: "POST", body: JSON.stringify(data) }),
  listAuditFlowTemplates: () => request<AuditFlowTemplate[]>("/audit-flow/templates"),
  createAuditFlowTemplate: (data: {
    name: string;
    description?: string;
    targets: string[];
    credentials: Array<{
      label?: string;
      credential_type: "ssh_password" | "ssh_key" | "winrm";
      username: string;
      secret: string;
      key_passphrase?: string;
      service_username?: string;
      service_secret?: string;
    }>;
    save_to_inventory?: boolean;
    inventory_scope?: { tags: string[]; site?: string | null } | null;
    cron_expression?: string;
    is_scheduled?: boolean;
    is_active?: boolean;
  }) => request<AuditFlowTemplate>("/audit-flow/templates", { method: "POST", body: JSON.stringify(data) }),
  updateAuditFlowTemplate: (
    id: number,
    data: {
      name?: string;
      description?: string;
      targets?: string[];
      credentials?: Array<{
        label?: string;
        credential_type: "ssh_password" | "ssh_key" | "winrm";
        username: string;
        secret: string;
        key_passphrase?: string;
        service_username?: string;
        service_secret?: string;
      }>;
      save_to_inventory?: boolean;
      inventory_scope?: { tags: string[]; site?: string | null } | null;
      cron_expression?: string | null;
      is_scheduled?: boolean;
      is_active?: boolean;
    }
  ) => request<AuditFlowTemplate>(`/audit-flow/templates/${id}`, { method: "PATCH", body: JSON.stringify(data) }),
  deleteAuditFlowTemplate: (id: number) =>
    request<void>(`/audit-flow/templates/${id}`, { method: "DELETE" }),
  runAuditFlowTemplate: (id: number) =>
    request<AuditFlowRun>(`/audit-flow/templates/${id}/run`, { method: "POST" }),
  getAuditFlowRun: (id: number) => request<AuditFlowRun>(`/audit-flow/runs/${id}`),
  compareAuditFlowRuns: (leftRunId: number, rightRunId: number) =>
    request<AuditFlowInventoryDriftReport>(
      `/audit-flow/runs/compare?left_run_id=${leftRunId}&right_run_id=${rightRunId}`
    ),
  getAuditFlowLogs: (id: number) => request<AuditFlowLogEntry[]>(`/audit-flow/runs/${id}/logs`),
  cancelAuditFlowRun: (id: number) =>
    request<AuditFlowRun>(`/audit-flow/runs/${id}/cancel`, { method: "POST" }),
  patchAuditFlowHosts: (
    id: number,
    hosts: Array<{
      id: number;
      selected?: boolean;
      profile_id?: number | null;
      credential_id?: number | null;
      extra_profiles?: Array<{ profile_id: number; selected: boolean }>;
    }>
  ) =>
    request<AuditFlowRun>(`/audit-flow/runs/${id}/hosts`, {
      method: "PATCH",
      body: JSON.stringify({ hosts }),
    }),
  addAuditFlowCredential: (
    id: number,
    data: {
      label?: string;
      credential_type: "ssh_password" | "ssh_key" | "winrm";
      username: string;
      secret: string;
      key_passphrase?: string;
      service_username?: string;
      service_secret?: string;
      host_id?: number;
    }
  ) =>
    request<AuditFlowRun>(`/audit-flow/runs/${id}/credentials`, {
      method: "POST",
      body: JSON.stringify(data),
    }),
  executeAuditFlow: (id: number) =>
    request<AuditFlowRun>(`/audit-flow/runs/${id}/execute`, { method: "POST" }),
  deleteAuditFlowRun: (id: number) => request<void>(`/audit-flow/runs/${id}`, { method: "DELETE" }),
  aagStatus: () => request<AagStatus>("/aag/status"),
  aagUsage: () => request<AagUsage>("/aag/usage"),
  aagConnection: () => request<AagConnection>("/aag/connection"),
  aagProviders: () => request<AagConnection[]>("/aag/providers"),
  saveAagConnection: (data: AagConnectionInput) =>
    request<AagConnection>("/aag/connection", { method: "PUT", body: JSON.stringify(data) }),
  selectAagProvider: (id: number) =>
    request<AagConnection>(`/aag/providers/${id}/select`, { method: "POST" }),
  deleteAagProvider: (id: number) => request<void>(`/aag/providers/${id}`, { method: "DELETE" }),
  testAagConnection: (providerId?: number) =>
    request<AagConnectionTestResult>(
      `/aag/connection/test${providerId != null ? buildQuery({ provider_id: providerId }) : ""}`,
      { method: "POST" },
    ),
  aagCalls: (params?: ListParams) =>
    request<PaginatedResponse<AagCallLogEntry>>(`/aag/calls${listQuery(params)}`),
  deleteAagCall: (id: number) => request<void>(`/aag/calls/${id}`, { method: "DELETE" }),
  aagTasks: (params?: { kind?: AagTaskKind; offset?: number; limit?: number }) =>
    request<PaginatedResponse<AagArtifact>>(`/aag/tasks${buildQuery(params)}`),
  createAagTask: (data: AagTaskInput) =>
    request<AagArtifact>("/aag/tasks", { method: "POST", body: JSON.stringify(data) }),
  deleteAagTask: (id: number) => request<void>(`/aag/tasks/${id}`, { method: "DELETE" }),
  retryAagTask: (id: number) => request<AagArtifact>(`/aag/tasks/${id}/retry`, { method: "POST" }),
  aagExplainCandidates: (runId: number) =>
    request<AagExplainCandidate[]>(`/aag/explain/candidates${buildQuery({ run_id: runId })}`),
  saveAagPackage: (id: number, data: AagPackageDraft) =>
    request<AagArtifact>(`/aag/tasks/${id}/draft`, { method: "PUT", body: JSON.stringify(data) }),
  acceptAagPackage: (id: number) => request<AagArtifact>(`/aag/tasks/${id}/accept`, { method: "POST" }),
};
