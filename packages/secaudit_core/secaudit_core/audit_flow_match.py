"""Score CRE profiles against a host OS fingerprint.

Matching is family-first (ubuntu vs rhel vs windows_server), then version, then
edition/variant. Token overlap is not used for auto-selection: a random SSH host
must not land on the alphabetically first Linux profile.
"""

from __future__ import annotations

import re
from typing import TypedDict

_VERSION_RE = re.compile(r"(\d+(?:\.\d+)*)")
_ANSI_RE = re.compile(
    r"(?:\x1b\[[0-?]*[ -/]*[@-~]|\x1b[@-Z\\-_]|\x1b\][^\x07]*(?:\x07|\x1b\\)|\x9b[0-?]*[ -/]*[@-~])"
)
_CSI_LEFTOVER_RE = re.compile(r"\[[?][0-9;]*[A-Za-z]")
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

AUTO_SELECT_MIN = 70
AMBIGUITY_GAP = 8

_OS_CATEGORY_SLUGS = frozenset({"linux-platform", "windows-platform", "network-platform"})
_GENERIC_OS_NAMES = frozenset({"linux", "windows", "*", "any", "unix"})
_GENERIC_LABEL_HINTS = ("pci dss", "pci-dss", "fstek", "fstec")


def sanitize_probe_text(text: str | None) -> str:
    """Strip terminal control sequences from SSH/nmap probe output."""
    if not text:
        return ""
    cleaned = text.replace("\r\n", "\n").replace("\r", "\n")
    cleaned = _ANSI_RE.sub("", cleaned)
    cleaned = _CSI_LEFTOVER_RE.sub("", cleaned)
    cleaned = _CTRL_RE.sub("", cleaned)
    cleaned = cleaned.replace("\ufffd", "").replace("█", "")
    return "\n".join(line.strip() for line in cleaned.splitlines() if line.strip())


def display_os_guess(value: str | None) -> str | None:
    cleaned = sanitize_probe_text(value)
    if not cleaned:
        return None
    for first in cleaned.splitlines():
        if _is_port_service_line(first):
            continue
        letters = sum(ch.isalpha() for ch in first)
        if letters < 3:
            continue
        return first[:256]
    return None


def _is_port_service_line(text: str | None) -> bool:
    blob = (text or "").strip()
    return bool(re.match(r"^\d{1,5}/[A-Za-z0-9._+-]+", blob))


class ProfileMatchInput(TypedDict, total=False):
    id: int
    profile_name: str
    os_name: str | None
    os_version: str | None
    os_vendor: str | None
    platform: str
    category_slug: str


class Fingerprint(TypedDict, total=False):
    platform: str | None
    os_name: str | None
    os_version: str | None
    vendor: str | None
    raw: str
    family: str | None
    variant: str | None
    pretty: str | None
    source: str


class ProfileScore(TypedDict):
    profile_id: int
    profile_name: str
    confidence: int


class MatchDecision(TypedDict):
    profile_id: int | None
    profile_name: str | None
    confidence: int
    alternatives: list[ProfileScore]
    auto_select: bool
    skip_reason: str | None
    skip_detail: str | None


_LINUX_HINTS = (
    "linux",
    "ubuntu",
    "debian",
    "rhel",
    "red hat",
    "centos",
    "alma",
    "almalinux",
    "rocky",
    "fedora",
    "suse",
    "opensuse",
    "astra",
    "alt linux",
    "oracle linux",
    "azure linux",
    "redos",
    "alteros",
    "atlant",
    "talos",
)
_WINDOWS_HINTS = ("windows", "microsoft windows", "win32", "win64")
_NETWORK_HINTS = (
    "cisco",
    "ios-xe",
    "ios xe",
    "nx-os",
    "nxos",
    "juniper",
    "junos",
    "mikrotik",
    "routeros",
    "eltex",
    "huawei",
    "vrp",
    "fortinet",
    "fortigate",
    "fortios",
    "arista",
    "palo alto",
    "pan-os",
    "xiaomi",
    "miwifi",
    "openwrt",
)

# Longer / more specific aliases first.
_FAMILY_PATTERNS: tuple[tuple[str, str], ...] = (
    ("almalinux", "alma"),
    ("alma linux", "alma"),
    ("rockylinux", "rocky"),
    ("rocky linux", "rocky"),
    ("oracle linux", "oracle"),
    ("oraclelinux", "oracle"),
    ("red hat enterprise", "rhel"),
    ("redhat", "rhel"),
    ("red hat", "rhel"),
    ("azure linux", "azure"),
    ("azurelinux", "azure"),
    ("alt linux", "alt"),
    ("altlinux", "alt"),
    ("open suse", "opensuse"),
    ("opensuse-tumbleweed", "opensuse"),
    ("opensuse-slowroll", "opensuse"),
    ("opensuse-leap", "opensuse"),
    ("opensuse", "opensuse"),
    ("suse linux enterprise", "sles"),
    ("atlantos", "atlantos"),
    ("atlant os", "atlantos"),
    ("router os", "mikrotik"),
    ("routeros", "mikrotik"),
    ("mikrotik", "mikrotik"),
    ("palo alto", "paloalto"),
    ("pan-os", "paloalto"),
    ("fortigate", "fortinet"),
    ("fortinet", "fortinet"),
    ("fortios", "fortinet"),
    ("cisco ios", "cisco"),
    ("ios-xe", "cisco"),
    ("nx-os", "cisco"),
    ("windows server", "windows_server"),
    ("xiaoqiang", "xiaomi"),
    ("miwifi", "xiaomi"),
    ("mi wifi", "xiaomi"),
    ("xiaomi", "xiaomi"),
    ("openwrt", "xiaomi"),
)

_ID_TO_FAMILY = {
    "ubuntu": "ubuntu",
    "debian": "debian",
    "rhel": "rhel",
    "centos": "centos",
    "almalinux": "alma",
    "alma": "alma",
    "rocky": "rocky",
    "ol": "oracle",
    "oraclelinux": "oracle",
    "astra": "astra",
    "redos": "redos",
    "altlinux": "alt",
    "alt": "alt",
    "mariner": "azure",
    "azurelinux": "azure",
    "atlantos": "atlantos",
    "opensuse": "opensuse",
    "opensuse-leap": "opensuse",
    "opensuse-tumbleweed": "opensuse",
    "opensuse-slowroll": "opensuse",
    "sles": "sles",
    "sled": "sles",
    "fedora": "fedora",
    "talos": "talos",
    "cisco": "cisco",
    "ios": "cisco",
    "junos": "juniper",
    "juniper": "juniper",
    "mikrotik": "mikrotik",
    "routeros": "mikrotik",
    "eltex": "eltex",
    "huawei": "huawei",
    "vrp": "huawei",
    "fortinet": "fortinet",
    "fortigate": "fortinet",
    "arista": "arista",
    "eos": "arista",
    "panos": "paloalto",
    "xiaomi": "xiaomi",
    "openwrt": "xiaomi",
    "xiaoqiang": "xiaomi",
    "windows": "windows",
    "windows_server": "windows_server",
}

_FAMILY_KEYWORDS: tuple[tuple[str, str], ...] = (
    ("ubuntu", "ubuntu"),
    ("debian", "debian"),
    ("centos", "centos"),
    ("fedora", "fedora"),
    ("astra", "astra"),
    ("redos", "redos"),
    ("talos", "talos"),
    ("cisco", "cisco"),
    ("juniper", "juniper"),
    ("junos", "juniper"),
    ("eltex", "eltex"),
    ("huawei", "huawei"),
    ("arista", "arista"),
    ("rhel", "rhel"),
    ("alma", "alma"),
    ("rocky", "rocky"),
    ("sles", "sles"),
    ("suse", "opensuse"),
)

_VARIANT_PATTERNS: tuple[tuple[str, str], ...] = (
    ("special edition", "smolensk"),
    ("smolensk", "smolensk"),
    ("смоленск", "smolensk"),
    ("community edition", "orel"),
    ("orel", "orel"),
    ("орёл", "orel"),
    ("орел", "orel"),
    ("voronezh", "voronezh"),
    ("voronej", "voronezh"),
    ("воронеж", "voronezh"),
    (" eltex_esr", "esr"),
    ("eltex esr", "esr"),
    (" esr-", "esr"),
    ("_esr", "esr"),
    (" eltex_mes", "mes"),
    ("eltex mes", "mes"),
    (" mes-", "mes"),
    ("_mes", "mes"),
)

_WINDOWS_BUILD_RELEASE = {
    26100: "2025",
    25398: "2022",
    20348: "2022",
    19045: "10",
    19044: "10",
    19043: "10",
    19042: "10",
    19041: "10",
    18363: "10",
    17763: "2019",
    14393: "2016",
    9600: "2012",
    7601: "2008",
    7600: "2008",
}


def infer_platform(text: str, open_ports: list[int] | None = None) -> str | None:
    blob = (text or "").lower()
    ports = set(open_ports or [])
    if any(h in blob for h in _WINDOWS_HINTS):
        return "windows"
    if any(h in blob for h in _NETWORK_HINTS):
        return "network"
    if any(h in blob for h in _LINUX_HINTS):
        return "linux"
    if ports & {5985, 5986, 3389, 445} and 22 not in ports:
        return "windows"
    if ports & {23, 161, 830} and 445 not in ports and 3389 not in ports:
        return "network"
    if 22 in ports:
        return "linux"
    return None


def _parse_os_release(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in (text or "").splitlines():
        if "=" not in line or line.strip().startswith("#"):
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if not key or key in fields:
            continue
        fields[key] = value.strip().strip('"').strip("'")
    return fields


def _os_release_id(text: str) -> str | None:
    fields = _parse_os_release(text)
    raw = (fields.get("ID") or "").strip().lower()
    return raw or None


def detect_family(text: str, *, os_id: str | None = None) -> str | None:
    blob = (text or "").lower()
    if os_id:
        mapped = _ID_TO_FAMILY.get(os_id.lower())
        if mapped:
            return mapped
    for needle, family in _FAMILY_PATTERNS:
        if needle in blob:
            return family
    if os_id:
        like = os_id.lower()
        for needle, family in _FAMILY_PATTERNS:
            if needle.replace(" ", "") == like.replace(" ", ""):
                return family
    for needle, family in _FAMILY_KEYWORDS:
        if re.search(rf"(?<![a-z0-9]){re.escape(needle)}(?![a-z0-9])", blob):
            return family
    if "windows" in blob:
        return "windows_server" if "server" in blob else "windows"
    return None


def detect_variant(text: str) -> str | None:
    blob = f" {(text or '').lower()} "
    for needle, variant in _VARIANT_PATTERNS:
        if needle in blob:
            return variant
    return None


def _version_tuple(version: str | None) -> tuple[int, ...]:
    if not version:
        return ()
    cleaned = version.strip().lower()
    if cleaned in {"*", "any", "all"}:
        return ()
    nums = [int(part) for part in re.findall(r"\d+", cleaned)[:4]]
    while len(nums) > 1 and nums[-1] == 0:
        nums.pop()
    return tuple(nums)


def _windows_product_type(text: str) -> int | None:
    match = re.search(r"producttype\s*[:=]\s*(\d+)", text, re.IGNORECASE)
    if match:
        return int(match.group(1))
    return None


def _windows_build(text: str) -> int | None:
    match = re.search(r"build(?:number)?\s*[:=]\s*(\d+)", text, re.IGNORECASE)
    if match:
        return int(match.group(1))
    match = re.search(r"\b10\.0\.(\d{4,5})\b", text)
    if match:
        return int(match.group(1))
    match = re.search(r"\b6\.3\.(\d{4,5})\b", text)
    if match:
        return int(match.group(1))
    match = re.search(r"\b6\.1\.(\d{4,5})\b", text)
    if match:
        return int(match.group(1))
    return None


def _windows_caption_release(caption: str) -> str | None:
    blob = caption.lower()
    for year in ("2025", "2022", "2019", "2016", "2012", "2008"):
        if year in blob:
            return year
    if re.search(r"windows\s*11\b", blob):
        return "11"
    if re.search(r"windows\s*10\b", blob):
        return "10"
    if re.search(r"windows\s*8\.1\b", blob) or "8.1" in blob:
        return "8.1"
    if re.search(r"windows\s*7\b", blob):
        return "7"
    return None


def _windows_identity(text: str) -> tuple[str | None, str | None]:
    blob = text or ""
    lower = blob.lower()
    product_type = _windows_product_type(blob)
    is_server = product_type in {2, 3} or "windows server" in lower or (
        "server" in lower and "windows" in lower
    )
    caption_release = _windows_caption_release(blob)
    build = _windows_build(blob)
    build_release = None
    if build:
        if build >= 22000 and not is_server:
            build_release = "11"
        else:
            build_release = _WINDOWS_BUILD_RELEASE.get(build)
            if build_release == "2019" and not is_server:
                build_release = "10"
            elif build_release == "2012" and not is_server:
                build_release = "8.1"
            elif build_release == "2008" and not is_server:
                build_release = "7"
            elif build_release == "2025" and not is_server:
                build_release = "11"
    release = caption_release or build_release
    if is_server:
        return "windows_server", release
    if "windows" in lower or product_type == 1:
        return "windows", release
    return None, release


def _linux_pretty(fields: dict[str, str], raw: str) -> str | None:
    pretty = fields.get("PRETTY_NAME") or fields.get("NAME")
    if pretty:
        return display_os_guess(pretty) or pretty.strip()[:256]
    for line in sanitize_probe_text(raw).splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or "PRETTY_NAME" in stripped:
            continue
        if stripped.lower().startswith("version="):
            continue
        if _is_port_service_line(stripped):
            continue
        if stripped.lower().startswith(("mac-vendor", "device-type")):
            continue
        if ":" in stripped and not stripped.lower().startswith("operating system:"):
            key = stripped.split(":", 1)[0].strip().lower()
            if key in {
                "static hostname",
                "pretty hostname",
                "icon name",
                "chassis",
                "machine id",
                "boot id",
                "cpe os name",
                "kernel",
                "architecture",
                "hardware vendor",
                "hardware model",
                "firmware version",
            }:
                continue
        shown_line = stripped
        if shown_line.lower().startswith("operating system:"):
            shown_line = shown_line.split(":", 1)[1].strip()
        shown = display_os_guess(shown_line)
        if shown and len(shown) < 200:
            return shown
    return None


def pretty_fingerprint(fp: Fingerprint) -> str:
    shown = display_os_guess(str(fp.get("pretty") or ""))
    if shown and not _is_port_service_line(shown):
        return shown
    parts = [fp.get("os_name"), fp.get("os_version")]
    label = " ".join(p for p in parts if p).strip()
    if label:
        return label[:256]
    for line in sanitize_probe_text(fp.get("raw") or "").splitlines():
        if _is_port_service_line(line):
            continue
        shown = display_os_guess(line)
        if shown:
            return shown
    return ""


def is_generic_os_profile(profile: ProfileMatchInput) -> bool:
    label = f"{profile.get('profile_name') or ''}".lower()
    if any(hint in label for hint in _GENERIC_LABEL_HINTS):
        return True
    name = (profile.get("os_name") or "").strip().lower()
    version = (profile.get("os_version") or "").strip().lower()
    return name in _GENERIC_OS_NAMES and version in {"", "*", "any", "all"}


def is_os_profile(profile: ProfileMatchInput) -> bool:
    slug = (profile.get("category_slug") or "").strip().lower()
    if slug == "services":
        return False
    if slug in _OS_CATEGORY_SLUGS:
        return True
    return profile.get("platform") in {"linux", "windows", "network"}


def _profile_family(profile: ProfileMatchInput) -> str | None:
    hay = " ".join(
        filter(
            None,
            [
                profile.get("os_name"),
                profile.get("os_vendor"),
                profile.get("profile_name"),
            ],
        )
    )
    family = detect_family(hay)
    if family == "windows" and "server" in hay.lower():
        return "windows_server"
    if family == "opensuse" and any(token in hay.lower() for token in ("sles", "enterprise")):
        return "sles"
    return family


def _profile_release(profile: ProfileMatchInput, family: str | None) -> str | None:
    explicit = _profile_version(profile)
    if family in {"windows", "windows_server"}:
        hay = " ".join(
            filter(
                None,
                [
                    profile.get("os_name"),
                    profile.get("os_version"),
                    profile.get("profile_name"),
                ],
            )
        )
        _, release = _windows_identity(hay)
        return release or explicit
    return explicit


def _profile_version(profile: ProfileMatchInput) -> str | None:
    version = profile.get("os_version")
    if version and str(version).strip() not in {"*", "any", "all"}:
        return str(version)
    hay = f"{profile.get('profile_name') or ''}"
    match = _VERSION_RE.search(hay)
    return match.group(1) if match else None


def score_profile(fp: Fingerprint, profile: ProfileMatchInput) -> int:
    if not is_os_profile(profile):
        return 0
    platform = (fp.get("platform") or "").lower()
    if not platform or profile.get("platform") != platform:
        return 0

    if is_generic_os_profile(profile):
        return 0

    fp_family = fp.get("family")
    pr_family = _profile_family(profile)
    if not fp_family or not pr_family or fp_family != pr_family:
        return 0

    score = 60
    fp_ver = _version_tuple(fp.get("os_version"))
    pr_ver = _version_tuple(_profile_release(profile, pr_family))
    if pr_ver and fp_ver:
        n = min(len(fp_ver), len(pr_ver))
        if fp_ver[:n] == pr_ver[:n]:
            score += 25
        else:
            return 0
    elif not pr_ver:
        score += 15
    elif not fp_ver:
        score += 5

    fp_variant = fp.get("variant")
    pr_variant = detect_variant(
        " ".join(filter(None, [profile.get("os_name"), profile.get("profile_name")]))
    )
    if fp_variant and pr_variant:
        if fp_variant == pr_variant:
            score += 10
        else:
            score -= 20
    elif pr_variant and fp_variant is None:
        score -= 5

    return max(0, min(100, score))


def rank_profiles(fp: Fingerprint, profiles: list[ProfileMatchInput], *, limit: int = 5) -> list[ProfileScore]:
    ranked: list[ProfileScore] = []
    for profile in profiles:
        confidence = score_profile(fp, profile)
        if confidence <= 0:
            continue
        ranked.append({"profile_id": profile["id"], "profile_name": profile["profile_name"], "confidence": confidence})
    ranked.sort(key=lambda item: (-item["confidence"], item["profile_name"]))
    return ranked[:limit]


def decide_profile(
    fp: Fingerprint,
    profiles: list[ProfileMatchInput],
    *,
    authenticated: bool,
    limit: int = 5,
) -> MatchDecision:
    ranked = rank_profiles(fp, profiles, limit=limit)
    if not ranked:
        return {
            "profile_id": None,
            "profile_name": None,
            "confidence": 0,
            "alternatives": [],
            "auto_select": False,
            "skip_reason": "no_matching_profile",
            "skip_detail": "No matching compliance profile",
        }

    top = ranked[0]
    alternatives = ranked[1:]
    source = fp.get("source") or "ports"
    auto = bool(authenticated and source == "facts" and top["confidence"] >= AUTO_SELECT_MIN)
    skip_reason: str | None = None
    skip_detail: str | None = None
    if auto and alternatives and top["confidence"] - alternatives[0]["confidence"] < AMBIGUITY_GAP:
        auto = False
        skip_reason = "ambiguous_profile"
        skip_detail = "Several profiles fit this host; confirm the match"
    elif not auto:
        skip_reason = "low_confidence"
        skip_detail = "Profile match needs confirmation"

    return {
        "profile_id": top["profile_id"],
        "profile_name": top["profile_name"],
        "confidence": top["confidence"],
        "alternatives": alternatives,
        "auto_select": auto,
        "skip_reason": None if auto else skip_reason,
        "skip_detail": None if auto else skip_detail,
    }


def review_skip_without_auth(
    *,
    probe_skip: str | None,
    has_profile: bool,
    discovered: bool,
) -> tuple[str | None, str | None]:
    """Status on the Review step when login was not confirmed.

    A live host with a suggested profile is available; "unreachable" is only for
    addresses we could not identify at all.
    """
    if probe_skip == "auth_failed":
        return "auth_failed", "No working credential pair"
    if has_profile:
        return None, None
    if discovered:
        return "no_matching_profile", "No matching compliance profile"
    return "unreachable", "No SSH/WinRM management port responded"


def fingerprint_from_facts(
    *,
    platform: str | None,
    os_release: str | None = None,
    win_caption: str | None = None,
    nmap_os: str | None = None,
    services: str | None = None,
    open_ports: list[int] | None = None,
) -> Fingerprint:
    os_release = sanitize_probe_text(os_release) or None
    win_caption = sanitize_probe_text(win_caption) or None
    nmap_os = sanitize_probe_text(nmap_os) or None
    services = sanitize_probe_text(services) or None
    auth_parts = [p for p in (os_release, win_caption) if p]
    nmap_parts = [p for p in (nmap_os, services) if p]
    raw = "\n".join(auth_parts + nmap_parts)
    auth_blob = "\n".join(auth_parts)
    fields = _parse_os_release(os_release or "")
    os_id = _os_release_id(os_release or "") or _os_release_id(raw)

    family = detect_family(auth_blob, os_id=os_id) if auth_blob else None
    if not family:
        family = detect_family(raw, os_id=os_id)

    win_family, win_release = (None, None)
    win_text = win_caption or (raw if "windows" in raw.lower() else "")
    if win_text and ("windows" in win_text.lower() or "producttype" in win_text.lower()):
        win_family, win_release = _windows_identity(win_text)
        family = win_family or family

    guessed = platform
    if win_family:
        guessed = "windows"
    elif not guessed:
        guessed = infer_platform(raw, open_ports)
    if family in {"windows", "windows_server"}:
        guessed = "windows"
    elif family in {
        "cisco",
        "juniper",
        "mikrotik",
        "eltex",
        "huawei",
        "fortinet",
        "arista",
        "paloalto",
        "xiaomi",
    }:
        guessed = "network"
    elif family:
        guessed = "linux"

    os_name = None
    os_version = None
    vendor = None
    pretty = None
    variant = detect_variant(auth_blob or raw)
    source = "ports"
    if auth_parts:
        source = "facts"
    elif nmap_parts:
        source = "nmap"

    if guessed == "windows":
        os_name = "Windows Server" if family == "windows_server" else "Windows"
        vendor = "Microsoft"
        os_version = win_release
        caption_line = (win_caption or "").strip().splitlines()[0].strip() if win_caption else ""
        pretty = caption_line or (f"{os_name} {os_version}".strip() if os_version else os_name)
        family = family or win_family or ("windows_server" if "server" in (pretty or "").lower() else "windows")
    elif guessed == "linux":
        os_version = fields.get("VERSION_ID") or None
        if not os_version:
            ver_src = fields.get("PRETTY_NAME") or auth_blob or (nmap_os or "")
            ver = _VERSION_RE.search(ver_src)
            os_version = ver.group(1) if ver else None
        os_name = fields.get("NAME") or fields.get("ID") or (family.title() if family else "Linux")
        vendor = fields.get("HOME_URL")
        pretty = _linux_pretty(fields, os_release or auth_blob or "")
        if not pretty and nmap_os and not _is_port_service_line(nmap_os):
            pretty = nmap_os
        if not pretty:
            pretty = f"{os_name} {os_version}".strip() if os_version else os_name
        family = family or detect_family(pretty or raw, os_id=os_id)
    elif guessed == "network":
        family = family or detect_family(raw)
        os_name = (family or "Network").replace("_", " ").title()
        vendor = family
        ver_src = auth_blob or (nmap_os if nmap_os and not _is_port_service_line(nmap_os) else "")
        ver = _VERSION_RE.search(ver_src)
        os_version = ver.group(1) if ver else None
        pretty_source = auth_blob or (nmap_os if nmap_os and not _is_port_service_line(nmap_os) else "") or os_name
        pretty = (sanitize_probe_text(pretty_source) or os_name).splitlines()[0].strip()[:256]
        if _is_port_service_line(pretty):
            pretty = os_name
        if family == "xiaomi":
            dist = fields.get("DISTRIB_DESCRIPTION") or fields.get("DISTRIB_ID") or "Xiaomi MiWiFi"
            rel = fields.get("DISTRIB_RELEASE")
            pretty = f"{dist} {rel}".strip() if rel else dist
        if family == "eltex" and not variant:
            variant = detect_variant(raw)

    if family == "windows_server" or family == "windows":
        guessed = "windows"

    return {
        "platform": guessed,
        "os_name": os_name,
        "os_version": os_version,
        "vendor": vendor,
        "raw": raw[:2000],
        "family": family,
        "variant": variant,
        "pretty": (pretty or "")[:256] or None,
        "source": source if guessed else "ports",
    }


APP_SELECT_MIN = 80

# (needles in nmap blob, ports that imply the app, profile name needles)
_APP_SIGNATURES: tuple[tuple[tuple[str, ...], tuple[int, ...], tuple[str, ...]], ...] = (
    (("nginx",), (80, 443), ("nginx",)),
    (("httpd", "apache"), (80, 443), ("apache", "httpd")),
    (("tomcat",), (8080, 8443), ("tomcat",)),
    (("postgresql", "postgres"), (5432,), ("postgresql", "postgres")),
    (("mariadb",), (3306,), ("mariadb",)),
    (("mysql",), (3306,), ("mysql",)),
    (("mongodb", "mongo"), (27017,), ("mongodb", "mongo")),
    (("docker",), (2376, 2375), ("docker",)),
    (("kubernetes", "kube-apiserver", "kube"), (6443,), ("kubernetes", "kube")),
    (("haproxy",), (80, 443, 8080), ("haproxy",)),
    (("bind", "named"), (53,), ("bind",)),
    (("cassandra",), (9042,), ("cassandra",)),
)


def rank_application_profiles(
    *,
    services: str | None,
    open_ports: list[int] | None,
    profiles: list[ProfileMatchInput],
    limit: int = 8,
) -> list[ProfileScore]:
    """Suggest Services-catalog profiles from nmap products/ports, never as an OS substitute."""
    blob = (services or "").lower()
    ports = set(open_ports or [])
    ranked: list[ProfileScore] = []
    for profile in profiles:
        slug = (profile.get("category_slug") or "").strip().lower()
        if slug and slug != "services":
            continue
        if slug != "services" and profile.get("platform") in {"linux", "windows", "network"}:
            if profile.get("os_name"):
                continue
        hay = " ".join(
            filter(None, [profile.get("profile_name"), profile.get("os_name")])
        ).lower()
        best = 0
        for needles, app_ports, names in _APP_SIGNATURES:
            if not any(name in hay for name in names):
                continue
            product_hit = any(needle in blob for needle in needles)
            port_hit = bool(ports & set(app_ports))
            if product_hit:
                best = max(best, 90)
            elif port_hit:
                best = max(best, 62)
        if best:
            ranked.append({"profile_id": profile["id"], "profile_name": profile["profile_name"], "confidence": best})
    ranked.sort(key=lambda item: (-item["confidence"], item["profile_name"]))
    return ranked[:limit]


def merge_extra_profiles(existing: list | None, suggested: list[ProfileScore] | list[dict]) -> list[dict]:
    """Keep operator selection when re-probing; auto-check only high-confidence apps."""
    previous = {int(item["profile_id"]): item for item in (existing or []) if item.get("profile_id")}
    merged: list[dict] = []
    for item in suggested:
        profile_id = int(item["profile_id"])
        prev = previous.get(profile_id)
        selected = (
            bool(prev.get("selected"))
            if prev is not None and "selected" in prev
            else int(item.get("confidence") or 0) >= APP_SELECT_MIN
        )
        merged.append(
            {
                "profile_id": profile_id,
                "profile_name": item.get("profile_name") or item.get("label"),
                "confidence": int(item.get("confidence") or 0),
                "selected": selected,
            }
        )
    return merged
