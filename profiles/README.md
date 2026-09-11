# Profiles catalog

Compliance profile packages are **not** included in this public repository.

Place packages under this directory (or set `PROFILES_SOURCE_PATH`). Lab Compose mounts `${PROFILES_SOURCE_PATH:-./profiles}` into the API and workers as `/profiles:ro`.

Imported packages are copied at runtime to `PROFILES_STORAGE_PATH` (default `/data/profiles/<profile_name>`).

## What a profile is

A **profile** is a check package for a target system. SecAudit:

1. reads metadata (`description.json`);
2. loads rules (`profile_rules.json`);
3. runs audit scripts (SSH / WinRM / Python) or evaluates SCAP on the host;
4. parses stdout with each rule’s `match_pattern`;
5. records **PASS / FAIL / SKIP / ERROR** in job results.

Optional **remediation** scripts and an Ansible **compliance playbook** can ship in the same package.

## Package layout

### Minimal

```text
MyProfile/
├── description.json
├── profile_rules.json
└── audit.sh                 # stem must match check_script in rules
```

### Full (recommended)

```text
MyProfile/
├── description.json
├── profile_rules.json
├── Ubuntu24.sh              # audit (Linux SSH)
├── Ubuntu24_remediation.sh  # optional remediation (_remediation in the name)
├── Ubuntu24.yml             # optional compliance playbook
├── scripts/                 # optional extra remediation scripts
├── rule_changelog.json      # created/updated by the UI
└── playbook_changelog.json  # created/updated by the UI
```

Typical script types:

| Extension | Role | Notes |
|-----------|------|--------|
| `.sh` | Audit / remediation | Linux over SSH |
| `.ps1` | Audit / remediation | Windows over WinRM |
| `.py` | Audit / remediation | Network / services (Python executor) |
| `.yml` / `.yaml` | Compliance playbook | Ansible; **not** treated as an audit script |

Remediation files must contain `_remediation` in the filename and may live in the package root or under `scripts/`.

### Catalog folders (optional grouping)

```text
profiles/
├── Linux Platform/<PackageName>/
├── Windows Platform/<PackageName>/
├── Network Platform/<PackageName>/
│   └── _shared/             # shared modules (not audit scripts)
└── Services/<PackageName>/
```

Flat packages directly under `profiles/` are also fine.

## `description.json`

```json
{
  "profile_name": "Ubuntu 24",
  "is_active": true,
  "version": "1.0",
  "overview": "Secure configuration baseline for Ubuntu 24",
  "purpose": "Assess the security configuration of Ubuntu 24",
  "os": {
    "name": "Ubuntu Linux",
    "vendor": "Canonical Ltd.",
    "version": "24.04"
  },
  "encoding": "utf-8",
  "profile_family": "custom",
  "profile_rules": "profile_rules.json",
  "category_slug": "linux-platform",
  "compliance_playbook": "Ubuntu24.yml",
  "compliance_playbook_version": "1.0"
}
```

| Field | Required | Purpose |
|-------|----------|---------|
| `profile_name` | yes (on import) | Unique profile key / storage folder name |
| `os` and/or `software` | yes | Target OS or product metadata |
| `profile_rules` | yes* | Rules file name (`profile_rules.json` by default) |
| `version` | recommended | Package version |
| `overview` / `purpose` | optional | Short / long description |
| `category_slug` | optional | e.g. `linux-platform`, `windows-platform`, `network-platform`, `services` |
| `compliance_playbook` | optional | Ansible YAML filename in the package root |
| `compliance_playbook_version` | optional | Playbook version (often `1.0`) |
| `encoding` | optional | Script output encoding hint |
| `source_format` | optional | `custom` (default), or `xccdf` / `oval` after SCAP import |

\* Or ship `profile_rules.json` without an explicit key.

Services profiles typically use a `software` block (`name`, `vendor`, `category`, `version`) instead of (or in addition to) `os`.

## `profile_rules.json`

```json
{
  "version": 1,
  "format": "secaudit.profile_rules",
  "rules": [
    {
      "num": "1",
      "requirement_id": "RULE1",
      "title": "Ensure that the cramfs kernel module is not available",
      "explanation": "...",
      "criticality": "LOW",
      "check_script": "Ubuntu24",
      "match_pattern": "RULE1=(.*)"
    }
  ]
}
```

| Field | Purpose |
|-------|---------|
| `requirement_id` | Stable rule id (e.g. `RULE1`) |
| `check_script` | Stem of the audit script (`Ubuntu24` → `Ubuntu24.sh`) |
| `match_pattern` | Interpreter pattern applied to script stdout |
| `title` / `explanation` / `criticality` | UI and reporting metadata |

Every check script stem must appear in at least one rule’s `check_script`, and those rules need a compilable `match_pattern`.

### Audit script output contract

Scripts should emit one result line per rule, for example:

```text
RULE1= PASS: cramfs is not available
RULE2= FAIL: freevxfs is loaded
RULE3= SKIP: not applicable
RULE4= ERROR: unable to evaluate
```

Allowed statuses: **PASS**, **FAIL**, **SKIP**, **ERROR**.

## Compliance playbooks

An optional Ansible playbook can ship with the profile and appears in the UI under **Playbooks** as a `compliance_template`.

Declare it in `description.json`:

```json
"compliance_playbook": "Ubuntu24.yml",
"compliance_playbook_version": "1.0"
```

Resolution order:

1. filename from `compliance_playbook`;
2. otherwise the first `*_compliance.yml` / `*_compliance.yaml` in the package root.

Notes:

- Playbook YAML is **not** discovered as an audit check script.
- Use a normal Ansible playbook against `hosts: all` (facts/become as needed).
- Edits in the UI bump `compliance_playbook_version` and append `playbook_changelog.json`.
- Platform playbooks (Linux / Windows / Network) can also be created independently in the UI; package playbooks are the profile-bundled templates.

## Importing

1. Put the package under `./profiles` (or your `PROFILES_SOURCE_PATH`).
2. UI: **Profiles** → discover / import, or upload ZIP/XML (custom or SCAP).
3. API examples:
   - `GET /api/v1/profiles/discover`
   - `POST /api/v1/profiles/import?package_path=/profiles/MyProfile&category_id=…`
   - `POST /api/v1/profiles/import/upload` (multipart)

SCAP/XCCDF/OVAL uploads are materialized into the same canonical layout (`source_format=xccdf|oval`).

## Related docs

- [docs/en/getting-started.md](../docs/en/getting-started.md)
- [docs/production-guide.md](../docs/production-guide.md)
- API Swagger: `/docs` when the stack is running
