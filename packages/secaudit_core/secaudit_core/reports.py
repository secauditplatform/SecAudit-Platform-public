from datetime import UTC, datetime
import re
from io import BytesIO
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from jinja2 import Environment, select_autoescape
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from secaudit_core.enums import CheckStatus
from secaudit_core.models import Host, Job, JobRun, Profile
from secaudit_core.profile_packages import load_profile_rules_metadata
from secaudit_core.report_i18n import (
    get_report_strings,
    normalize_report_locale,
    run_status_label,
    status_labels_for_locale,
)

try:
    from xhtml2pdf import pisa
except ImportError:
    pisa = None

_FONT_DIR_CANDIDATES = (
    Path("/usr/share/fonts/truetype/dejavu"),
    Path("C:/Windows/Fonts"),
)
_FONTS_REGISTERED = False

_STATUS_ACCENT = {
    "pass": "#2f7d4a",
    "fail": "#c62828",
    "skip": "#c9a227",
    "error": "#5a6572",
}


def _resolve_font_file(*names: str) -> Path | None:
    for directory in _FONT_DIR_CANDIDATES:
        if not directory.is_dir():
            continue
        for name in names:
            candidate = directory / name
            if candidate.is_file():
                return candidate
    return None


def _ensure_pdf_fonts() -> None:
    global _FONTS_REGISTERED
    if _FONTS_REGISTERED:
        return

    from reportlab.lib.fonts import addMapping
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont

    regular = _resolve_font_file("DejaVuSans.ttf", "arial.ttf", "segoeui.ttf")
    bold = _resolve_font_file("DejaVuSans-Bold.ttf", "arialbd.ttf", "segoeuib.ttf")
    mono = _resolve_font_file("DejaVuSansMono.ttf", "cour.ttf", "consola.ttf")
    if regular is None:
        raise RuntimeError("No Unicode font found for PDF generation (install fonts-dejavu-core)")

    pdfmetrics.registerFont(TTFont("DejaVuSans", str(regular)))
    pdfmetrics.registerFont(TTFont("DejaVuSans-Bold", str(bold or regular)))
    pdfmetrics.registerFont(TTFont("DejaVuMono", str(mono or regular)))
    addMapping("DejaVuSans", 0, 0, "DejaVuSans")
    addMapping("DejaVuSans", 1, 0, "DejaVuSans-Bold")
    addMapping("DejaVuSans", 0, 1, "DejaVuSans")
    addMapping("DejaVuSans", 1, 1, "DejaVuSans-Bold")
    _FONTS_REGISTERED = True


def _pdf_font_paths() -> dict[str, str]:
    regular = _resolve_font_file("DejaVuSans.ttf", "arial.ttf", "segoeui.ttf")
    bold = _resolve_font_file("DejaVuSans-Bold.ttf", "arialbd.ttf", "segoeuib.ttf")
    mono = _resolve_font_file("DejaVuSansMono.ttf", "cour.ttf", "consola.ttf")
    if regular is None:
        raise RuntimeError("No Unicode font found for PDF generation (install fonts-dejavu-core)")

    return {
        "font_regular": str(regular).replace("\\", "/"),
        "font_bold": str(bold or regular).replace("\\", "/"),
        "font_mono": str(mono or regular).replace("\\", "/"),
    }


def _pdf_link_callback(uri: str, _rel) -> str:
    candidate = uri[7:] if uri.startswith("file://") else uri
    path = Path(candidate).resolve()
    allowed_roots = [root.resolve() for root in _FONT_DIR_CANDIDATES if root.is_dir()]
    if path.is_file() and any(path == root or root in path.parents for root in allowed_roots):
        return str(path)
    raise ValueError("PDF resource is outside the approved font directories")


_REPORT_ENV = Environment(
    autoescape=select_autoescape(
        enabled_extensions=("html", "htm", "xml"),
        default_for_string=True,
        default=True,
    )
)

# Table/bgcolor-first layout: xhtml2pdf often ignores div backgrounds and % width fills.
# Keep column widths as HTML attributes and avoid text overflow between cells.
REPORT_TEMPLATE = _REPORT_ENV.from_string("""{% macro pdf_spacer(height_pt=8) %}
<table width="100%" cellpadding="0" cellspacing="0"><tr><td style="height: {{ height_pt }}pt; font-size: 1pt; line-height: 1pt; padding: 0;">&nbsp;</td></tr></table>
{% endmacro %}
{% macro check_card(row) %}
{% if for_pdf %}
{% set sev_styles = {
  'high': {'bg': '#fdeceb', 'border': '#f5c4c0', 'color': '#a61f1f'},
  'medium': {'bg': '#fbf4df', 'border': '#ead9a8', 'color': '#8a7018'},
  'low': {'bg': '#e7f4eb', 'border': '#bde0c8', 'color': '#24663c'},
  'other': {'bg': '#eef2f6', 'border': '#d7dee7', 'color': '#4a5568'}
} %}
{% set sev = sev_styles.get(row.severity_bucket, sev_styles.other) %}
<table class="check-card-pdf" width="100%" cellpadding="0" cellspacing="0">
  <tr>
    <td class="check-card-pdf__shell" style="border: 1px solid #e2e8f0; border-left: 4pt solid {{ row.status_color }}; background-color: #f8fafc; padding: 10pt 12pt 10pt 14pt;">
      <table width="100%" cellpadding="0" cellspacing="0">
        <tr>
          <td valign="top" width="74%">
            <font class="pdf-title" size="2"><b>{{ row.rule_name }}</b></font><br/>
            <table cellpadding="0" cellspacing="0" style="margin-top: 4pt;">
              <tr>
                <td bgcolor="#eef2f6" style="padding: 2pt 8pt 2pt 6pt;">
                  <font face="DejaVuMono" size="1" color="#667788">{{ row.rule_id }}</font>
                </td>
                {% if row.severity %}
                <td bgcolor="{{ sev.bg }}" style="padding: 2pt 6pt; border: 1px solid {{ sev.border }};">
                  <font size="1" color="{{ sev.color }}"><b>{{ row.severity }}</b></font>
                </td>
                {% endif %}
              </tr>
            </table>
          </td>
          <td valign="top" align="right" width="26%">
            <span class="badge b-{{ row.status }}">{{ row.status_label }}</span>
          </td>
        </tr>
      </table>
      {% if row.description or row.risk or row.location %}
      {{ pdf_spacer(8) }}
      <table class="pdf-req-panel" width="100%" cellpadding="0" cellspacing="0" bgcolor="#ffffff" style="border: 1px solid #e2e8f0;">
        <tr>
          <td style="padding: 10pt 12pt;">
            {% if row.description %}
            <font class="pdf-label" size="1" color="#7a8796"><b>{{ t.description|upper }}</b></font><br/>
            <font class="pdf-text" size="1" color="#2d3748">{{ row.description }}</font>
            {% endif %}
            {% if row.risk or row.location %}
            {% if row.description %}
            <table width="100%" cellpadding="0" cellspacing="0"><tr><td style="padding-top: 10pt; border-top: 1px solid #e8edf2; font-size: 1pt; line-height: 1pt;">&nbsp;</td></tr></table>
            {{ pdf_spacer(8) }}
            {% endif %}
            <table width="100%" cellpadding="0" cellspacing="0">
              <tr>
                {% if row.risk and row.location %}
                <td valign="top" width="48%" style="padding: 8pt 6pt 8pt 10pt; background-color: #ffffff; border: 1px solid #e8edf2; border-left: 3pt solid #e8a0a0;">
                  <font class="pdf-label" size="1" color="#7a8796"><b>{{ t.risk|upper }}</b></font><br/>
                  <font class="pdf-text" size="1" color="#2d3748">{{ row.risk }}</font>
                </td>
                <td valign="top" width="48%" style="padding: 8pt 10pt 8pt 6pt; background-color: #ffffff; border: 1px solid #e8edf2; border-left: 3pt solid #8eb4e8;">
                  <font class="pdf-label" size="1" color="#7a8796"><b>{{ t.location|upper }}</b></font><br/>
                  <font class="pdf-text-mono" face="DejaVuMono" size="1" color="#4a5568">{{ row.location }}</font>
                </td>
                {% elif row.risk %}
                <td valign="top" style="padding: 8pt 10pt; background-color: #ffffff; border: 1px solid #e8edf2; border-left: 3pt solid #e8a0a0;">
                  <font class="pdf-label" size="1" color="#7a8796"><b>{{ t.risk|upper }}</b></font><br/>
                  <font class="pdf-text" size="1" color="#2d3748">{{ row.risk }}</font>
                </td>
                {% elif row.location %}
                <td valign="top" style="padding: 8pt 10pt; background-color: #ffffff; border: 1px solid #e8edf2; border-left: 3pt solid #8eb4e8;">
                  <font class="pdf-label" size="1" color="#7a8796"><b>{{ t.location|upper }}</b></font><br/>
                  <font class="pdf-text-mono" face="DejaVuMono" size="1" color="#4a5568">{{ row.location }}</font>
                </td>
                {% endif %}
              </tr>
            </table>
            {% endif %}
          </td>
        </tr>
      </table>
      {% endif %}
      {% if row.message %}
      {{ pdf_spacer(8) }}
      <table class="pdf-result" width="100%" cellpadding="0" cellspacing="0" bgcolor="#ffffff" style="border: 1px solid #e2e8f0;">
        <tr>
          <td style="padding: 8pt 10pt;">
            <font class="pdf-label" size="1" color="#7a8796"><b>{{ t.result|upper }}</b></font><br/>
            <font class="pdf-result-text" size="1" color="#3d4b5c">{{ row.message }}</font>
          </td>
        </tr>
      </table>
      {% endif %}
    </td>
  </tr>
</table>
{% else %}
<div class="check-card check-card--{{ row.status }}">
  <div class="check-card__shell" style="--status-accent: {{ row.status_color }};">
    <div class="check-card__header">
      <div class="check-card__heading">
        <div class="check-card__title">{{ row.rule_name }}</div>
        <div class="check-card__toolbar">
          <span class="check-card__id">{{ row.rule_id }}</span>
          {% if row.severity %}
          <span class="sev-chip sev-chip--{{ row.severity_bucket }}">{{ row.severity }}</span>
          {% endif %}
        </div>
      </div>
      <span class="check-card__badge badge b-{{ row.status }}">{{ row.status_label }}</span>
    </div>
    {% if row.description or row.risk or row.location %}
    <div class="req-panel">
      {% if row.description %}
      <div class="req-panel__block req-panel__block--desc">
        <div class="req-panel__label">{{ t.description }}</div>
        <div class="req-panel__text">{{ row.description }}</div>
      </div>
      {% endif %}
      {% if row.risk or row.location %}
      <div class="req-panel__grid">
        {% if row.risk %}
        <div class="req-panel__block req-panel__block--risk">
          <div class="req-panel__label">{{ t.risk }}</div>
          <div class="req-panel__text">{{ row.risk }}</div>
        </div>
        {% endif %}
        {% if row.location %}
        <div class="req-panel__block req-panel__block--loc">
          <div class="req-panel__label">{{ t.location }}</div>
          <div class="req-panel__text req-panel__text--mono">{{ row.location }}</div>
        </div>
        {% endif %}
      </div>
      {% endif %}
    </div>
    {% endif %}
    {% if row.message %}
    <div class="check-card__result">
      <div class="check-card__result-label">{{ t.result }}</div>
      <div class="check-card__result-text">{{ row.message }}</div>
    </div>
    {% endif %}
  </div>
</div>
{% endif %}
{% endmacro %}
<!DOCTYPE html>
<html lang="{{ lang }}">
<head>
  <meta charset="UTF-8" />
  <title>SecAudit — {{ t.report_title }} #{{ run.id }}</title>
  <style>
    {% if for_pdf %}
    @font-face {
      font-family: DejaVuSans;
      src: url("{{ font_regular }}");
    }
    @font-face {
      font-family: DejaVuSans;
      font-weight: bold;
      src: url("{{ font_bold }}");
    }
    @font-face {
      font-family: DejaVuMono;
      src: url("{{ font_mono }}");
    }
    {% endif %}

    @page {
      size: A4;
      margin: 1.4cm 1.2cm 1.8cm;
      @frame footer {
        -pdf-frame-content: footerContent;
        bottom: 0.5cm;
        margin-left: 1.2cm;
        margin-right: 1.2cm;
        height: 0.9cm;
      }
    }

    body {
      font-family: {% if for_pdf %}DejaVuSans{% else %}Helvetica, Arial, "Segoe UI"{% endif %}, sans-serif;
      font-size: 9pt;
      line-height: 1.45;
      color: #1c2430;
      margin: 0;
      padding: 0;
      background: #ffffff;
    }

    @media screen {
      body { background: #e8edf2; padding: 24px; }
      .sheet {
        max-width: 860px;
        margin: 0 auto;
        box-shadow: 0 12px 40px rgba(24, 34, 48, 0.12);
      }
    }

    @media print {
      html, body {
        -webkit-print-color-adjust: exact;
        print-color-adjust: exact;
      }
      .check-card__shell {
        break-inside: avoid;
        page-break-inside: avoid;
      }
      .host-band {
        break-after: avoid;
        page-break-after: avoid;
      }
      #footerContent { display: none; }
    }

    table { border-collapse: collapse; table-layout: fixed; }
    .check-card-pdf,
    .check-card-pdf table,
    .pdf-req-panel,
    .pdf-result { table-layout: auto; }
    .check-card-pdf { margin-bottom: 10pt; }
    .check-card-pdf td { vertical-align: top; word-wrap: break-word; }
    .check-card-pdf__shell { background-color: #f8fafc; }
    .pdf-title {
      font-size: 11pt;
      font-weight: bold;
      color: #182230;
      line-height: 1.35;
    }
    .pdf-label {
      font-size: 6.5pt;
      font-weight: bold;
      letter-spacing: 0.06em;
      text-transform: uppercase;
      color: #7a8796;
    }
    .pdf-text {
      font-size: 8.5pt;
      line-height: 1.55;
      color: #2d3748;
    }
    .pdf-text-mono {
      font-size: 8pt;
      line-height: 1.5;
      color: #4a5568;
    }
    .pdf-result-text {
      font-size: 8pt;
      line-height: 1.45;
      color: #3d4b5c;
    }
    .sheet { background: #ffffff; }

    .mh-brand {
      font-size: 14pt;
      font-weight: bold;
      color: #ffffff;
      letter-spacing: 0.3pt;
    }
    .mh-brand .mark { color: #ff8a80; }
    .mh-meta {
      text-align: right;
      font-size: 8pt;
      color: #a8b4c2;
      line-height: 1.4;
    }
    .mh-meta strong { color: #ffffff; }

    .pad { padding: 14pt 16pt 10pt; }

    .title {
      font-size: 12.5pt;
      font-weight: bold;
      color: #182230;
      margin: 0 0 3pt;
    }
    .subtitle {
      font-size: 8pt;
      color: #667788;
      margin: 0;
    }

    .score { text-align: center; vertical-align: middle; }
    .score-value {
      font-size: 20pt;
      font-weight: bold;
      color: {{ compliance_color }};
      line-height: 1;
    }
    .score-unit {
      font-size: 9pt;
      color: #667788;
      font-weight: bold;
    }
    .score-label {
      font-size: 6.5pt;
      font-weight: bold;
      letter-spacing: 0.35pt;
      text-transform: uppercase;
      color: #7a8796;
      padding-top: 3pt;
    }

    .bar-cell {
      font-size: 1pt;
      line-height: 4pt;
      height: 4pt;
    }

    .h2 {
      font-size: 8.5pt;
      font-weight: bold;
      color: #182230;
      margin: 14pt 0 7pt;
      padding: 0 0 4pt;
      border-bottom: 1px solid #d7dee7;
    }

    .meta td {
      padding: 5pt 0;
      vertical-align: top;
      font-size: 8pt;
      border-bottom: 1px solid #eef2f6;
    }
    .meta .k {
      width: 14%;
      color: #7a8796;
      font-size: 6.5pt;
      font-weight: bold;
      text-transform: uppercase;
      letter-spacing: 0.25pt;
      padding-right: 4pt;
    }
    .meta .v {
      width: 36%;
      color: #1c2430;
      padding-right: 10pt;
      word-wrap: break-word;
    }

    .metric {
      text-align: center;
      vertical-align: middle;
      padding: 9pt 4pt;
    }
    .metric-value {
      font-size: 14pt;
      font-weight: bold;
      line-height: 1.1;
    }
    .metric-label {
      font-size: 6.5pt;
      font-weight: bold;
      letter-spacing: 0.3pt;
      text-transform: uppercase;
      color: #7a8796;
      padding-top: 2pt;
    }
    .m-pass { color: #24663c; }
    .m-fail { color: #a61f1f; }
    .m-skip { color: #8a7018; }
    .m-error { color: #5a6572; }

    .results { width: 100%; font-size: 7.5pt; }
    .results th {
      background-color: #eef2f6;
      color: #3d4b5c;
      font-size: 6.5pt;
      font-weight: bold;
      text-transform: uppercase;
      letter-spacing: 0.25pt;
      text-align: left;
      padding: 5pt 6pt;
      border-top: 1px solid #d7dee7;
      border-bottom: 1px solid #d7dee7;
    }
    .results td {
      padding: 5pt 6pt;
      border-bottom: 1px solid #eef2f6;
      vertical-align: top;
      word-wrap: break-word;
      overflow: hidden;
    }
    .results tr.alt td { background-color: #f8fafc; }
    .c-host { font-weight: bold; color: #182230; font-size: 8pt; }

    .check-card { margin: 0 0 12px; }
    .check-card__shell {
      position: relative;
      background: linear-gradient(180deg, #f8fafc 0%, #ffffff 100%);
      border: 1px solid #e2e8f0;
      border-radius: 10px;
      padding: 14px 16px 14px 18px;
      box-shadow: 0 1px 2px rgba(24, 34, 48, 0.04);
      overflow: hidden;
    }
    .check-card__shell::before {
      content: "";
      position: absolute;
      left: 0;
      top: 0;
      bottom: 0;
      width: 4px;
      background: var(--status-accent, #5a6572);
      border-radius: 10px 0 0 10px;
    }
    .check-card__header {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 10px;
    }
    .check-card__heading { min-width: 0; flex: 1; }
    .check-card__title {
      font-size: 11pt;
      font-weight: bold;
      color: #182230;
      line-height: 1.35;
      margin: 0 0 6px;
    }
    .check-card__toolbar {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 8px;
    }
    .check-card__id {
      font-family: "SF Mono", "Consolas", "Courier New", monospace;
      font-size: 7.5pt;
      color: #667788;
      background-color: #eef2f6;
      padding: 2px 8px;
      border-radius: 999px;
      letter-spacing: 0.02em;
    }
    .check-card__badge { flex-shrink: 0; border-radius: 999px; }
    .sev-chip {
      font-size: 7pt;
      font-weight: bold;
      letter-spacing: 0.04em;
      text-transform: uppercase;
      padding: 2px 8px;
      border-radius: 999px;
      border: 1px solid transparent;
    }
    .sev-chip--high { color: #a61f1f; background-color: #fdeceb; border-color: #f5c4c0; }
    .sev-chip--medium { color: #8a7018; background-color: #fbf4df; border-color: #ead9a8; }
    .sev-chip--low { color: #24663c; background-color: #e7f4eb; border-color: #bde0c8; }
    .sev-chip--other { color: #4a5568; background-color: #eef2f6; border-color: #d7dee7; }

    .req-panel {
      margin-top: 2px;
      padding: 12px 14px;
      border: 1px solid #e2e8f0;
      border-radius: 8px;
      background: linear-gradient(180deg, rgba(248, 250, 252, 0.92) 0%, #ffffff 100%);
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.8);
    }
    .req-panel__block--desc + .req-panel__grid {
      margin-top: 12px;
      padding-top: 12px;
      border-top: 1px solid #e8edf2;
    }
    .req-panel__label {
      font-size: 6.5pt;
      font-weight: bold;
      letter-spacing: 0.06em;
      text-transform: uppercase;
      color: #7a8796;
      margin-bottom: 4px;
    }
    .req-panel__text {
      font-size: 8.5pt;
      line-height: 1.55;
      color: #2d3748;
      max-width: 72ch;
    }
    .req-panel__text--mono {
      font-family: "SF Mono", "Consolas", "Courier New", monospace;
      font-size: 8pt;
      color: #4a5568;
    }
    .req-panel__grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 10px;
    }
    .req-panel__block--risk,
    .req-panel__block--loc {
      padding: 10px 12px;
      background-color: #ffffff;
      border: 1px solid #e8edf2;
      border-radius: 6px;
    }
    .req-panel__block--risk { border-left: 3px solid #e8a0a0; }
    .req-panel__block--loc { border-left: 3px solid #8eb4e8; }

    .check-card__result {
      margin-top: 12px;
      padding: 10px 12px;
      background-color: #ffffff;
      border: 1px solid #e2e8f0;
      border-radius: 6px;
    }
    .check-card__result-label {
      font-size: 6.5pt;
      font-weight: bold;
      letter-spacing: 0.06em;
      text-transform: uppercase;
      color: #7a8796;
      margin-bottom: 4px;
    }
    .check-card__result-text {
      font-size: 8pt;
      line-height: 1.45;
      color: #3d4b5c;
    }

    .check-list { width: 100%; }
    .check-list--pdf { width: 100%; }

    .host-band td {
      background-color: #e8eef5;
      color: #182230;
      font-size: 8.5pt;
      font-weight: bold;
      padding: 8pt 10pt;
      border-top: 1px solid #cfd8e3;
      border-bottom: 1px solid #cfd8e3;
      text-align: left;
      word-wrap: break-word;
    }
    .host-band .host-k {
      color: #667788;
      font-size: 6.5pt;
      font-weight: bold;
      text-transform: uppercase;
      letter-spacing: 0.35pt;
    }

    .badge {
      font-size: 6.5pt;
      font-weight: bold;
      padding: 2pt 7pt;
      border-radius: 999px;
    }
    .b-pass { color: #24663c; background-color: #e7f4eb; }
    .b-fail { color: #a61f1f; background-color: #fdeceb; }
    .b-skip { color: #8a7018; background-color: #fbf4df; }
    .b-error { color: #5a6572; background-color: #eef1f4; }

    .empty {
      text-align: center;
      padding: 14pt;
      color: #7a8796;
      background-color: #f8fafc;
      border: 1px solid #d7dee7;
      font-size: 8pt;
    }

    .foot {
      margin-top: 12pt;
      padding-top: 7pt;
      border-top: 1px solid #d7dee7;
      font-size: 6.5pt;
      color: #8a96a4;
    }

    #footerContent {
      font-size: 6.5pt;
      color: #8a96a4;
      text-align: center;
    }
  </style>
</head>
<body>
  <div class="sheet">
    <table width="100%" cellpadding="0" cellspacing="0" bgcolor="#182230">
      <tr>
        <td style="padding: 12pt 14pt;">
          <table width="100%" cellpadding="0" cellspacing="0">
            <tr>
              <td class="mh-brand"><span class="mark">■</span> SecAudit</td>
              <td class="mh-meta">
                {{ t.report_title }}<br />
                <strong>{{ t.run_prefix }}{{ run.id }}</strong>
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
    <table width="100%" cellpadding="0" cellspacing="0">
      <tr><td bgcolor="{{ compliance_color }}" class="bar-cell">&nbsp;</td></tr>
    </table>

    <div class="pad">
      <table width="100%" cellpadding="0" cellspacing="0" bgcolor="#f3f6f9">
        <tr>
          <td style="padding: 11pt 12pt;">
            <table width="100%" cellpadding="0" cellspacing="0">
              <tr>
                <td style="vertical-align: middle; padding-right: 10pt;">
                  <div class="title">{{ t.page_title }}</div>
                  <p class="subtitle">{{ t.page_subtitle }}</p>
                </td>
                <td class="score" width="108">
                  <div class="score-value">{{ compliance }}<span class="score-unit">%</span></div>
                  <div class="score-label">{{ t.compliance }}</div>
                </td>
              </tr>
            </table>
            <table width="100%" cellpadding="0" cellspacing="0" style="margin-top: 8pt;">
              <tr>
                {% if compliance_bar > 0 %}
                <td bgcolor="{{ compliance_color }}" width="{{ compliance_bar }}%" class="bar-cell">&nbsp;</td>
                {% endif %}
                {% if compliance_rest > 0 %}
                <td bgcolor="#d5dde6" width="{{ compliance_rest }}%" class="bar-cell">&nbsp;</td>
                {% endif %}
              </tr>
            </table>
          </td>
        </tr>
      </table>

      <div class="h2">{{ t.section_params }}</div>
      <table class="meta" width="100%" cellpadding="0" cellspacing="0">
        <tr>
          <td class="k" width="14%">{{ t.job }}</td>
          <td class="v" width="36%">{{ job_name }}</td>
          <td class="k" width="14%">{{ t.standard }}</td>
          <td class="v" width="36%">{{ profile_name }}</td>
        </tr>
        <tr>
          <td class="k" width="14%">{{ t.status }}</td>
          <td class="v" width="36%">{{ run_status_label }}</td>
          <td class="k" width="14%">{{ t.hosts }}</td>
          <td class="v" width="36%">{{ host_count }}</td>
        </tr>
        <tr>
          <td class="k" width="14%">{{ t.created }}</td>
          <td class="v" width="36%">{{ created_at }}</td>
          <td class="k" width="14%">{{ t.finished }}</td>
          <td class="v" width="36%">{{ finished_at }}</td>
        </tr>
      </table>

      <div class="h2">{{ t.section_summary }}</div>
      <table width="100%" cellpadding="0" cellspacing="0">
        <tr>
          <td width="25%" style="padding-right: 4pt;">
            <table width="100%" cellpadding="0" cellspacing="0" bgcolor="#f4faf6">
              <tr><td class="metric">
                <div class="metric-value m-pass">{{ passed }}</div>
                <div class="metric-label">{{ t.passed }}</div>
              </td></tr>
            </table>
          </td>
          <td width="25%" style="padding-right: 4pt;">
            <table width="100%" cellpadding="0" cellspacing="0" bgcolor="#fdf4f3">
              <tr><td class="metric">
                <div class="metric-value m-fail">{{ failed }}</div>
                <div class="metric-label">{{ t.failed }}</div>
              </td></tr>
            </table>
          </td>
          <td width="25%" style="padding-right: 4pt;">
            <table width="100%" cellpadding="0" cellspacing="0" bgcolor="#fbf8ee">
              <tr><td class="metric">
                <div class="metric-value m-skip">{{ skipped }}</div>
                <div class="metric-label">{{ t.skipped }}</div>
              </td></tr>
            </table>
          </td>
          <td width="25%">
            <table width="100%" cellpadding="0" cellspacing="0" bgcolor="#f5f7f9">
              <tr><td class="metric">
                <div class="metric-value m-error">{{ errors }}</div>
                <div class="metric-label">{{ t.error }}</div>
              </td></tr>
            </table>
          </td>
        </tr>
      </table>

      <div class="h2">{{ t.section_details }} · {{ total_checks }}</div>
      {% if host_groups %}
      {% for group in host_groups %}
      <table class="results" width="100%" cellpadding="0" cellspacing="0"{% if not loop.first %} style="margin-top: 10pt;"{% endif %}>
        <tr class="host-band">
          <td bgcolor="#e8eef5">
            <font class="host-k" color="#667788" size="1"><b>{{ t.host|upper }}</b></font><br/>
            {{ group.host }}
          </td>
        </tr>
      </table>
      {% if for_pdf %}
      <table class="check-list check-list--pdf" width="100%" cellpadding="0" cellspacing="0">
        {% for row in group.rows %}
        <tr><td style="padding-bottom: 6pt;">{{ check_card(row) }}</td></tr>
        {% endfor %}
      </table>
      {% else %}
      <div class="check-list">
        {% for row in group.rows %}
        {{ check_card(row) }}
        {% endfor %}
      </div>
      {% endif %}
      {% endfor %}
      {% else %}
      <div class="empty">{{ t.empty }}</div>
      {% endif %}

      <div class="foot">
        SecAudit · {{ t.generated }} {{ generated_at }} · {{ t.checks }}: {{ total_checks }} · {{ t.hosts }}: {{ host_count }}
      </div>
    </div>
  </div>

  <div id="footerContent">
    SecAudit · {{ t.run_prefix }}{{ run.id }} · {{ generated_at }}
  </div>
</body>
</html>
""")


def build_report_summary_dict(
    run_id: int,
    checks: list,
    *,
    waived_check_ids: set[int] | None = None,
) -> dict:
    waived_ids = waived_check_ids or set()
    passed = sum(1 for c in checks if c.status == CheckStatus.PASS)
    failed = sum(1 for c in checks if c.status == CheckStatus.FAIL)
    skipped = sum(1 for c in checks if c.status == CheckStatus.SKIP)
    errors = sum(1 for c in checks if c.status == CheckStatus.ERROR)
    waived = sum(
        1
        for c in checks
        if c.status == CheckStatus.FAIL and getattr(c, "id", None) in waived_ids
    )
    total = len(checks)
    compliance_raw = round((passed / total) * 100, 2) if total else 0.0
    # Waived FAILs count toward compliant checks without rewriting stored status.
    compliance = round(((passed + waived) / total) * 100, 2) if total else 0.0

    return {
        "job_run_id": run_id,
        "total_checks": total,
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "errors": errors,
        "waived": waived,
        "compliance_percent": compliance,
        "compliance_percent_raw": compliance_raw,
    }


def fetch_run_report_context_sync(
    db: Session, run_id: int
) -> tuple[JobRun, object | None, dict[int, Host]] | None:
    job_run = db.execute(
        select(JobRun)
        .options(
            selectinload(JobRun.check_results),
            selectinload(JobRun.job).selectinload(Job.profile).selectinload(Profile.rules),
        )
        .where(JobRun.id == run_id)
    ).scalar_one_or_none()
    if not job_run:
        return None

    profile = job_run.job.profile if job_run.job else None
    host_ids = {c.host_id for c in job_run.check_results}
    hosts = {
        host.id: host
        for host in db.execute(select(Host).where(Host.id.in_(host_ids))).scalars().all()
    }
    return job_run, profile, hosts




def _format_dt(value: datetime | None, locale: str | None = None) -> str:
    if value is None:
        return "—"
    if normalize_report_locale(locale) == "en":
        return value.strftime("%b %d, %Y %H:%M UTC")
    return value.strftime("%d.%m.%Y %H:%M UTC")


def _compliance_color(compliance: float) -> str:
    if compliance >= 90:
        return "#2f7d4a"
    if compliance >= 70:
        return "#c9a227"
    return "#c62828"


def _soft_break(text: str, *, chunk: int = 18) -> str:
    """Insert zero-width spaces so xhtml2pdf can wrap long tokens inside fixed cells."""
    if not text:
        return text
    out: list[str] = []
    run = 0
    for char in text:
        out.append(char)
        if char in "-_./\\:@ ":
            out.append("\u200b")
            run = 0
            continue
        run += 1
        if run >= chunk:
            out.append("\u200b")
            run = 0
    return "".join(out)


def _group_rows_by_host(rows: list[dict]) -> list[dict]:
    groups: list[dict] = []
    for row in rows:
        host = row["host"]
        if not groups or groups[-1]["host"] != host:
            groups.append({"host": host, "rows": [row]})
        else:
            groups[-1]["rows"].append(row)
    return groups


def _index_rule_meta(lookup: dict[str, dict], meta: dict) -> None:
    for key in (meta.get("requirement_id"), meta.get("tech_name")):
        if key:
            lookup[str(key)] = meta


def _build_rules_lookup(profile) -> dict[str, dict]:
    lookup: dict[str, dict] = {}
    if profile is None:
        return lookup

    package_path = getattr(profile, "package_path", None)
    if package_path:
        package_dir = Path(package_path)
        if package_dir.is_dir():
            for meta in load_profile_rules_metadata(package_dir):
                _index_rule_meta(lookup, meta)

    orm_rules = getattr(profile, "rules", None)
    if orm_rules:
        for rule in orm_rules:
            tech_name = getattr(rule, "tech_name", None)
            if not tech_name or tech_name in lookup:
                continue
            _index_rule_meta(
                lookup,
                {
                    "tech_name": tech_name,
                    "requirement_id": tech_name,
                    "title": getattr(rule, "title", None),
                    "explanation": getattr(rule, "description", None),
                    "impact": None,
                    "scope": None,
                    "criticality": getattr(rule, "severity", None),
                },
            )
    return lookup


def _find_rule_meta(lookup: dict[str, dict], rule_tech_name: str) -> dict | None:
    return lookup.get(rule_tech_name)


def _severity_bucket(severity: str) -> str:
    normalized = (severity or "").strip().lower()
    if normalized in {"critical", "high", "критический", "высокий"}:
        return "high"
    if normalized in {"medium", "moderate", "средний"}:
        return "medium"
    if normalized in {"low", "info", "низкий"}:
        return "low"
    return "other"


def _profile_rule_display_name(meta: dict | None, tech_name: str) -> str:
    if not meta:
        return tech_name
    title = (meta.get("title") or meta.get("summary") or "").strip()
    if title:
        cleaned = re.sub(r"^\d+(?:\.\d+)*\s+", "", title)
        cleaned = re.sub(r"\s*\(.*?\)\s*$", "", cleaned).strip()
        return cleaned or title
    return str(meta.get("requirement_id") or meta.get("tech_name") or tech_name)


def _build_check_row(
    check,
    host_label: str,
    rules_lookup: dict[str, dict],
    status_labels: dict[str, str],
    *,
    for_pdf: bool,
) -> dict:
    meta = _find_rule_meta(rules_lookup, check.rule_tech_name)
    status = check.status.value
    rule_name = _profile_rule_display_name(meta, check.rule_tech_name)
    description = (
        (meta.get("explanation") or meta.get("description") or "").strip() if meta else ""
    )
    risk = ((meta.get("impact") or meta.get("risk") or "").strip() if meta else "")
    location = ((meta.get("scope") or meta.get("location") or "").strip() if meta else "")
    severity = (
        (meta.get("criticality") or meta.get("severity") or "").strip() if meta else ""
    )
    message = check.message or ""

    if for_pdf:
        host_label = _soft_break(host_label, chunk=16)
        rule_name = _soft_break(rule_name, chunk=24)
        description = _soft_break(description, chunk=32)
        risk = _soft_break(risk, chunk=24)
        location = _soft_break(location, chunk=24)
        severity = _soft_break(severity, chunk=16)
        message = _soft_break(message, chunk=28)

    return {
        "host": host_label,
        "rule_id": check.rule_tech_name,
        "rule_name": rule_name,
        "description": description,
        "risk": risk,
        "location": location,
        "severity": severity,
        "severity_bucket": _severity_bucket(severity) if severity else "other",
        "status": status,
        "status_label": status_labels.get(status, status.upper()),
        "status_color": _STATUS_ACCENT.get(status, "#5a6572"),
        "message": message,
    }


def render_run_report_html(job_run, profile, hosts: dict, *, for_pdf: bool = False, locale: str | None = None) -> str:
    checks = job_run.check_results or []
    passed = sum(1 for c in checks if c.status.value == "pass")
    failed = sum(1 for c in checks if c.status.value == "fail")
    skipped = sum(1 for c in checks if c.status.value == "skip")
    errors = sum(1 for c in checks if c.status.value == "error")
    total = len(checks)
    compliance = round((passed / total) * 100, 2) if total else 0.0
    compliance_bar = max(0, min(100, int(round(compliance))))
    compliance_rest = max(0, 100 - compliance_bar)
    if compliance_bar == 0 and compliance_rest == 0:
        compliance_rest = 100
    host_count = len({c.host_id for c in checks})
    run_status = getattr(job_run.status, "value", str(job_run.status)).lower()
    lang = normalize_report_locale(locale)
    t = get_report_strings(lang)
    status_labels = status_labels_for_locale(lang, for_pdf=for_pdf)
    rules_lookup = _build_rules_lookup(profile)

    rows = []
    for c in sorted(checks, key=lambda x: (x.host_id, x.rule_tech_name)):
        host = hosts.get(c.host_id)
        host_label = host.name if host else f"host#{c.host_id}"
        rows.append(
            _build_check_row(
                c,
                host_label,
                rules_lookup,
                status_labels,
                for_pdf=for_pdf,
            )
        )

    host_groups = _group_rows_by_host(rows) if rows else []

    if for_pdf:
        _ensure_pdf_fonts()
        font_paths = _pdf_font_paths()
    else:
        font_paths = {"font_regular": "", "font_bold": "", "font_mono": ""}

    return REPORT_TEMPLATE.render(
        run=job_run,
        lang=lang,
        t=t,
        for_pdf=for_pdf,
        **font_paths,
        job_name=_soft_break(job_run.job.name, chunk=24) if for_pdf and job_run.job else (job_run.job.name if job_run.job else "—"),
        profile_name=_soft_break(profile.profile_name, chunk=24) if for_pdf and profile else (profile.profile_name if profile else "—"),
        compliance=compliance,
        compliance_bar=compliance_bar,
        compliance_rest=compliance_rest,
        compliance_color=_compliance_color(compliance),
        passed=passed,
        failed=failed,
        skipped=skipped,
        errors=errors,
        total_checks=total,
        host_count=host_count,
        run_status_label=run_status_label(run_status, lang),
        created_at=_format_dt(job_run.created_at, lang),
        finished_at=_format_dt(job_run.finished_at, lang),
        generated_at=_format_dt(datetime.now(UTC), lang),
        rows=[],
        host_groups=host_groups,
    )


def render_run_report_pdf(job_run, profile, hosts: dict, *, locale: str | None = None) -> bytes:
    chromium = (
        shutil.which("chromium")
        or shutil.which("chromium-browser")
        or shutil.which("google-chrome")
    )
    if chromium:
        html = render_run_report_html(job_run, profile, hosts, for_pdf=False, locale=locale)
        with tempfile.TemporaryDirectory(prefix="secaudit-report-") as tmp:
            workdir = Path(tmp)
            html_path = workdir / "report.html"
            pdf_path = workdir / "report.pdf"
            profile_path = workdir / "chromium-profile"
            html_path.write_text(html, encoding="utf-8")
            result = subprocess.run(
                [
                    chromium,
                    "--headless",
                    "--no-sandbox",
                    "--disable-gpu",
                    "--disable-dev-shm-usage",
                    "--disable-breakpad",
                    "--disable-crash-reporter",
                    "--allow-file-access-from-files",
                    "--no-pdf-header-footer",
                    "--print-to-pdf-no-header",
                    "--print-to-pdf=" + str(pdf_path),
                    "--user-data-dir=" + str(profile_path),
                    html_path.as_uri(),
                ],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
                env={
                    **os.environ,
                    "HOME": str(workdir),
                    "XDG_CACHE_HOME": str(workdir / "cache"),
                    "XDG_CONFIG_HOME": str(workdir / "config"),
                },
            )
            if result.returncode != 0 or not pdf_path.is_file():
                detail = (result.stderr or result.stdout or "unknown Chromium error").strip()
                raise RuntimeError(f"Chromium PDF generation failed: {detail[-1000:]}")
            return pdf_path.read_bytes()

    if pisa is None:
        raise RuntimeError("No PDF renderer is installed")
    html = render_run_report_html(job_run, profile, hosts, for_pdf=True, locale=locale)
    buffer = BytesIO()
    result = pisa.CreatePDF(
        html,
        dest=buffer,
        encoding="utf-8",
        link_callback=_pdf_link_callback,
    )
    if result.err:
        raise RuntimeError(f"PDF generation failed with {result.err} error(s)")
    return buffer.getvalue()
