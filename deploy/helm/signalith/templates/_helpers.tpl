{{- define "signalith.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* The release's full name, the start of every object's name. Short
enough for "<fullname>-opensearch-certs" and pod names. */}}
{{- define "signalith.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 40 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 40 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 40 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "signalith.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/name: {{ include "signalith.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/* Selector labels; component is server, scanner, opensearch or setup. */}}
{{- define "signalith.selector" -}}
app.kubernetes.io/name: {{ include "signalith.name" .ctx }}
app.kubernetes.io/instance: {{ .ctx.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end }}

{{- define "signalith.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{- if .Values.image.digest -}}
{{ .Values.image.repository }}@{{ .Values.image.digest }}
{{- else -}}
{{ .Values.image.repository }}:{{ $tag }}
{{- end -}}
{{- end }}

{{- define "signalith.opensearchImage" -}}
{{- if .Values.opensearch.image.digest -}}
{{ .Values.opensearch.image.repository }}:{{ .Values.opensearch.image.tag }}@{{ .Values.opensearch.image.digest }}
{{- else -}}
{{ .Values.opensearch.image.repository }}:{{ .Values.opensearch.image.tag }}
{{- end -}}
{{- end }}

{{/* The agent port: server.agentPort, or 7779 when an upgrade with
--reuse-values kept values from before it existed. */}}
{{- define "signalith.agentPort" -}}{{ .Values.server.agentPort | default 7779 | int }}{{- end }}

{{- define "signalith.secretsName" -}}{{ include "signalith.fullname" . }}-secrets{{- end }}
{{- define "signalith.opensearchName" -}}{{ include "signalith.fullname" . }}-opensearch{{- end }}

{{/* The names OpenSearch's node certificate covers. */}}
{{- define "signalith.opensearchNames" -}}
{{- $os := include "signalith.opensearchName" . -}}
{{- $ns := .Release.Namespace -}}
{{ $os }},{{ $os }}.{{ $ns }},{{ $os }}.{{ $ns }}.svc,{{ $os }}.{{ $ns }}.svc.cluster.local,{{ $os }}-nodes,{{ $os }}-nodes.{{ $ns }}.svc
{{- end }}

{{/* Restricted Pod Security for a pod running as uid. */}}
{{- define "signalith.podSecurity" -}}
runAsNonRoot: true
runAsUser: {{ .uid }}
runAsGroup: {{ .uid }}
fsGroup: {{ .uid }}
fsGroupChangePolicy: OnRootMismatch
seccompProfile:
  type: RuntimeDefault
{{- end }}

{{- define "signalith.containerSecurity" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
privileged: false
capabilities:
  drop: [ALL]
{{- end }}

{{/*
"true" when the servers take plain syslog over UDP and TCP (5514 in the
pods, 514 on the Service), else "". server.syslog.plain true or false
decides. Unset (or "auto"), a new install takes syslog over TLS only, and
an upgrade keeps plain syslog as it was: on when the release's syslog
Service already takes UDP or TCP 514, as releases before 0.3.1 did.
(helm template, which reads nothing from the cluster, renders a new
install.)
*/}}
{{- define "signalith.plainSyslog" -}}
{{- $s := .Values.server.syslog -}}
{{- $on := false -}}
{{- if $s.enabled -}}
{{- if kindIs "bool" $s.plain -}}
{{- $on = $s.plain -}}
{{- else if .Release.IsUpgrade -}}
{{- $svc := lookup "v1" "Service" .Release.Namespace (printf "%s-syslog" (include "signalith.fullname" .)) -}}
{{- range (dig "spec" "ports" (list) $svc) -}}
{{- if eq (int (get . "port")) 514 -}}
{{- $on = true -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if $on }}true{{ end -}}
{{- end }}

{{/* The config file, signalith.yaml, for a server (role "") or a scanner. */}}
{{- define "signalith.config" -}}
{{- $ctx := .ctx -}}
{{- $v := $ctx.Values -}}
{{- $port := int $v.server.port -}}
{{- $public := $v.server.publicURL | default (printf "https://%s:%d" (include "signalith.fullname" $ctx) $port) -}}
{{- $tls := dict "mode" "auto" -}}
{{- if $v.server.tls.existingSecret -}}
{{- $tls = dict "mode" "files" -}}
{{- end -}}
{{- $server := dict "listen" (printf "0.0.0.0:%d" $port) "agent_listen" (printf "0.0.0.0:%d" (int (include "signalith.agentPort" $ctx))) "public_url" $public "tls" $tls -}}
{{- if $v.server.tls.existingSecret -}}
{{- $_ := set $server "tls_cert" "/run/signalith/tls/tls.crt" -}}
{{- $_ := set $server "tls_key" "/run/signalith/tls/tls.key" -}}
{{- end -}}
{{- $osc := dict "index_prefix" "signalith" "replicas" "auto" -}}
{{- if $v.opensearch.enabled -}}
{{- $_ := set $osc "url" (printf "https://%s:9200" (include "signalith.opensearchName" $ctx)) -}}
{{- $_ := set $osc "ca_file" "/run/signalith/secrets/opensearch-ca.pem" -}}
{{- $_ := set $osc "cert_file" "/run/signalith/secrets/opensearch-client.pem" -}}
{{- $_ := set $osc "key_file" "/run/signalith/secrets/opensearch-client-key.pem" -}}
{{- else -}}
{{- $_ := set $osc "url" (first $v.opensearch.external.urls) -}}
{{- if gt (len $v.opensearch.external.urls) 1 -}}
{{- $_ := set $osc "urls" $v.opensearch.external.urls -}}
{{- end -}}
{{- $_ := set $osc "ca_file" "/run/signalith/opensearch/ca.crt" -}}
{{- if eq $v.opensearch.external.auth "certificate" -}}
{{- $_ := set $osc "cert_file" "/run/signalith/opensearch/tls.crt" -}}
{{- $_ := set $osc "key_file" "/run/signalith/opensearch/tls.key" -}}
{{- end -}}
{{- end -}}
{{- $cluster := dict "leader_eligible" true -}}
{{- if eq .role "scanner" -}}
{{- $_ := set $cluster "role" "scanner" -}}
{{- end -}}
{{- $cfg := dict
  "server" $server
  "opensearch" $osc
  "search" (dict "default_earliest" "-24h" "max_events" 10000)
  "retention" (dict "days" 90)
  "auth" (dict "admin_user" "signalithadmin")
  "cluster" $cluster
  "detections" (dict "dir" "/var/lib/signalith/data/detections" "max_findings_per_run" 100 "catch_up" "6h")
  "lookups" (dict "dir" "/var/lib/signalith/data/lookups")
  "dashboards" (dict "dir" "/var/lib/signalith/data/dashboards" "stale_after" "2h")
-}}
{{- if and $v.server.syslog.enabled (ne .role "scanner") -}}
{{- $plain := ternary "0.0.0.0:5514" "" (include "signalith.plainSyslog" $ctx | eq "true") -}}
{{- $_ := set $cfg "syslog" (dict "udp" $plain "tcp" $plain "tls" "0.0.0.0:6514" "public_port" 514 "allow" $v.server.syslog.allow) -}}
{{- end -}}
{{- mustMergeOverwrite $cfg (deepCopy $v.server.config) | toYaml }}
{{- end }}
