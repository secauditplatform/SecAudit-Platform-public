{{- define "secaudit.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "secaudit.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "secaudit.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" -}}
{{- end -}}

{{- define "secaudit.labels" -}}
helm.sh/chart: {{ include "secaudit.chart" . | quote }}
{{ include "secaudit.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "secaudit.selectorLabels" -}}
app.kubernetes.io/name: {{ include "secaudit.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "secaudit.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "secaudit.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "secaudit.secretName" -}}
{{- if .Values.existingSecret -}}
{{- .Values.existingSecret -}}
{{- else -}}
{{- printf "%s-secrets" (include "secaudit.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "secaudit.apiImage" -}}
{{- printf "%s:%s" .Values.api.image.repository (default .Chart.AppVersion .Values.api.image.tag) -}}
{{- end -}}

{{- define "secaudit.workerImage" -}}
{{- printf "%s:%s" .Values.worker.image.repository (default .Chart.AppVersion .Values.worker.image.tag) -}}
{{- end -}}

{{- define "secaudit.beatImage" -}}
{{- printf "%s:%s" .Values.beat.image.repository (default .Chart.AppVersion .Values.beat.image.tag) -}}
{{- end -}}

{{- define "secaudit.frontendImage" -}}
{{- printf "%s:%s" .Values.frontend.image.repository (default .Chart.AppVersion .Values.frontend.image.tag) -}}
{{- end -}}

{{- define "secaudit.migrateImage" -}}
{{- printf "%s:%s" .Values.migrate.image.repository (default .Chart.AppVersion .Values.migrate.image.tag) -}}
{{- end -}}

{{- define "secaudit.profilesClaim" -}}
{{- if .Values.profiles.existingClaim -}}
{{- .Values.profiles.existingClaim -}}
{{- else -}}
{{- printf "%s-profiles" (include "secaudit.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "secaudit.profilesCatalogClaim" -}}
{{- if .Values.profiles.catalog.existingClaim -}}
{{- .Values.profiles.catalog.existingClaim -}}
{{- else -}}
{{- printf "%s-profiles-catalog" (include "secaudit.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "secaudit.profilesVolumeMounts" -}}
- name: profiles-data
  mountPath: /data/profiles
- name: profiles-catalog
  mountPath: /profiles
  {{- if .Values.profiles.catalog.readOnly }}
  readOnly: true
  {{- end }}
{{- end -}}

{{- define "secaudit.profilesVolumes" -}}
- name: profiles-data
  {{- if or .Values.profiles.persistence.enabled .Values.profiles.existingClaim }}
  persistentVolumeClaim:
    claimName: {{ include "secaudit.profilesClaim" . }}
  {{- else }}
  emptyDir: {}
  {{- end }}
- name: profiles-catalog
  {{- if .Values.profiles.catalog.hostPath }}
  hostPath:
    path: {{ .Values.profiles.catalog.hostPath | quote }}
    type: DirectoryOrCreate
  {{- else if .Values.profiles.catalog.existingClaim }}
  persistentVolumeClaim:
    claimName: {{ include "secaudit.profilesCatalogClaim" . }}
  {{- else }}
  emptyDir: {}
  {{- end }}
{{- end -}}

{{- define "secaudit.celeryLivenessProbe" -}}
livenessProbe:
  exec:
    command:
      - python
      - -c
      - import os; assert any(b"celery" in open(f"/proc/{p}/cmdline","rb").read() for p in os.listdir("/proc") if p.isdigit())
  initialDelaySeconds: 40
  periodSeconds: 30
  timeoutSeconds: 5
  failureThreshold: 3
{{- end -}}

{{- define "secaudit.env" -}}
envFrom:
  - configMapRef:
      name: {{ include "secaudit.fullname" . }}-config
  - secretRef:
      name: {{ include "secaudit.secretName" . }}
{{- end -}}
