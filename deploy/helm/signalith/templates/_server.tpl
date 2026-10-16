{{/*
The StatefulSet of Signalith servers (role "server") or of scanners (role
"scanner"). Both share OpenSearch, the setup Job's secrets and the cluster
key, so each pod joins the cluster by itself (docs/servers.md, Shared
settings and the cluster key).
*/}}
{{- define "signalith.statefulset" -}}
{{- $ctx := .ctx -}}
{{- $v := $ctx.Values -}}
{{- $p := .values -}}
{{- $role := .role -}}
{{- $full := include "signalith.fullname" $ctx -}}
{{- $name := ternary $full (printf "%s-scanner" $full) (eq $role "server") -}}
{{- $port := int $v.server.port -}}
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: {{ $name }}
  namespace: {{ $ctx.Release.Namespace }}
  labels:
    {{- include "signalith.labels" $ctx | nindent 4 }}
    app.kubernetes.io/component: {{ $role }}
spec:
  serviceName: {{ $full }}-pods
  replicas: {{ $p.replicas }}
  # New servers start together; each finds the cluster in OpenSearch.
  podManagementPolicy: Parallel
  selector:
    matchLabels:
      {{- include "signalith.selector" (dict "ctx" $ctx "component" $role) | nindent 6 }}
  template:
    metadata:
      labels:
        {{- include "signalith.selector" (dict "ctx" $ctx "component" $role) | nindent 8 }}
        {{- with $p.podLabels }}
        {{- toYaml . | nindent 8 }}
        {{- end }}
      annotations:
        checksum/config: {{ include (print $ctx.Template.BasePath "/configmap.yaml") $ctx | sha256sum }}
        {{- with $p.podAnnotations }}
        {{- toYaml . | nindent 8 }}
        {{- end }}
    spec:
      serviceAccountName: {{ $full }}
      # Signalith never talks to the Kubernetes API.
      automountServiceAccountToken: false
      enableServiceLinks: false
      terminationGracePeriodSeconds: {{ $v.server.terminationGracePeriodSeconds }}
      {{- with $v.imagePullSecrets }}
      imagePullSecrets:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      {{- with $p.priorityClassName }}
      priorityClassName: {{ . }}
      {{- end }}
      securityContext:
        {{- include "signalith.podSecurity" (dict "uid" 65532) | nindent 8 }}
      initContainers:
        # Copies the secrets into a memory-only folder as files of
        # Signalith's own, readable by it alone (Secret volumes are
        # group-readable), and makes the data folders on a new volume.
        - name: prepare
          image: {{ include "signalith.image" $ctx }}
          imagePullPolicy: {{ $v.image.pullPolicy }}
          command:
            - sh
            - -ec
            - |
              umask 077
              copy() { for f in "$1"/*; do [ -f "$f" ] && install -m 0400 "$f" "$2/"; done; return 0; }
              copy /in/secrets /run/signalith-secrets
              if [ -d /in/opensearch ]; then copy /in/opensearch /run/signalith-opensearch; fi
              if [ -d /in/tls ]; then copy /in/tls /run/signalith-tls; fi
              mkdir -p /var/lib/signalith/detections /var/lib/signalith/lookups /var/lib/signalith/dashboards /var/lib/signalith/archive
          securityContext:
            {{- include "signalith.containerSecurity" $ctx | nindent 12 }}
          resources:
            requests: { cpu: 10m, memory: 16Mi }
            limits: { memory: 64Mi }
          volumeMounts:
            - { name: secrets-in, mountPath: /in/secrets, readOnly: true }
            - { name: secrets, mountPath: /run/signalith-secrets }
            {{- if not $v.opensearch.enabled }}
            - { name: opensearch-in, mountPath: /in/opensearch, readOnly: true }
            - { name: opensearch, mountPath: /run/signalith-opensearch }
            {{- end }}
            {{- if $v.server.tls.existingSecret }}
            - { name: tls-in, mountPath: /in/tls, readOnly: true }
            - { name: tls, mountPath: /run/signalith-tls }
            {{- end }}
            - { name: data, mountPath: /var/lib/signalith }
      containers:
        - name: signalith
          image: {{ include "signalith.image" $ctx }}
          imagePullPolicy: {{ $v.image.pullPolicy }}
          args: [serve, -c, /etc/signalith/signalith.yaml]
          env:
            - name: POD_NAME
              valueFrom: { fieldRef: { fieldPath: metadata.name } }
            # This server's name on the Servers page, and the address the
            # other servers reach it at.
            - name: SIGNALITH_NODE_NAME
              value: "$(POD_NAME)"
            - name: SIGNALITH_NODE_URL
              value: "https://$(POD_NAME).{{ $full }}-pods.{{ $ctx.Release.Namespace }}.svc:{{ $port }}"
            - name: SIGNALITH_ADMIN_PASSWORD_FILE
              value: /run/signalith-secrets/initial-admin-password
            - name: SIGNALITH_INGEST_TOKEN_FILE
              value: /run/signalith-secrets/ingest-token
            - name: SIGNALITH_CLUSTER_KEY_FILE
              value: /run/signalith-secrets/cluster-key
            {{- if and (not $v.opensearch.enabled) (eq $v.opensearch.external.auth "password") }}
            - name: SIGNALITH_OPENSEARCH_USERNAME
              valueFrom: { secretKeyRef: { name: {{ $v.opensearch.external.existingSecret }}, key: username } }
            - name: SIGNALITH_OPENSEARCH_PASSWORD_FILE
              value: /run/signalith-opensearch/password
            {{- end }}
            {{- with $p.extraEnv }}
            {{- toYaml . | nindent 12 }}
            {{- end }}
          ports:
            - { name: https, containerPort: {{ $port }}, protocol: TCP }
            {{- if and $v.server.syslog.enabled (eq $role "server") }}
            - { name: syslog-udp, containerPort: 5514, protocol: UDP }
            - { name: syslog-tcp, containerPort: 5514, protocol: TCP }
            - { name: syslog-tls, containerPort: 6514, protocol: TCP }
            {{- end }}
          # /readyz and /livez answer on plain HTTP too (docs/servers.md,
          # Load balancers). A server waiting for OpenSearch is not ready,
          # but restarting it would not help, so only /livez restarts it.
          startupProbe:
            httpGet: { path: /livez, port: https, scheme: HTTP }
            periodSeconds: 5
            failureThreshold: 60
          livenessProbe:
            httpGet: { path: /livez, port: https, scheme: HTTP }
            periodSeconds: 20
            timeoutSeconds: 5
            failureThreshold: 6
          readinessProbe:
            httpGet: { path: /readyz, port: https, scheme: HTTP }
            periodSeconds: 10
            timeoutSeconds: 5
            failureThreshold: 3
          securityContext:
            {{- include "signalith.containerSecurity" $ctx | nindent 12 }}
          resources:
            {{- toYaml $p.resources | nindent 12 }}
          volumeMounts:
            - name: config
              mountPath: /etc/signalith/signalith.yaml
              subPath: {{ ternary "signalith.yaml" "scanner.yaml" (eq $role "server") }}
              readOnly: true
            - { name: data, mountPath: /var/lib/signalith }
            - { name: secrets, mountPath: /run/signalith-secrets, readOnly: true }
            {{- if not $v.opensearch.enabled }}
            - { name: opensearch, mountPath: /run/signalith-opensearch, readOnly: true }
            {{- end }}
            {{- if $v.server.tls.existingSecret }}
            - { name: tls, mountPath: /run/signalith-tls, readOnly: true }
            {{- end }}
            - { name: tmp, mountPath: /tmp }
      volumes:
        - name: config
          configMap: { name: {{ $full }}-config }
        - name: secrets-in
          secret:
            secretName: {{ include "signalith.secretsName" $ctx }}
            defaultMode: 0440
        - name: secrets
          emptyDir: { medium: Memory, sizeLimit: 1Mi }
        {{- if not $v.opensearch.enabled }}
        - name: opensearch-in
          secret:
            secretName: {{ required "opensearch.external.existingSecret is required when opensearch.enabled is false" $v.opensearch.external.existingSecret }}
            defaultMode: 0440
        - name: opensearch
          emptyDir: { medium: Memory, sizeLimit: 1Mi }
        {{- end }}
        {{- if $v.server.tls.existingSecret }}
        - name: tls-in
          secret:
            secretName: {{ $v.server.tls.existingSecret }}
            defaultMode: 0440
        - name: tls
          emptyDir: { medium: Memory, sizeLimit: 1Mi }
        {{- end }}
        - name: tmp
          emptyDir: { sizeLimit: 1Gi }
      {{- with $p.nodeSelector }}
      nodeSelector:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      {{- with $p.tolerations }}
      tolerations:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      affinity:
        {{- if $p.affinity }}
        {{- toYaml $p.affinity | nindent 8 }}
        {{- else }}
        # Servers on different nodes where possible, so one node going
        # down leaves the others running.
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
            - weight: 100
              podAffinityTerm:
                topologyKey: kubernetes.io/hostname
                labelSelector:
                  matchLabels:
                    {{- include "signalith.selector" (dict "ctx" $ctx "component" $role) | nindent 20 }}
        {{- end }}
      {{- with $p.topologySpreadConstraints }}
      topologySpreadConstraints:
        {{- toYaml . | nindent 8 }}
      {{- end }}
  volumeClaimTemplates:
    - metadata:
        name: data
        labels:
          {{- include "signalith.selector" (dict "ctx" $ctx "component" $role) | nindent 10 }}
      spec:
        accessModes: {{ toYaml $p.persistence.accessModes | nindent 10 }}
        {{- with $p.persistence.storageClass }}
        storageClassName: {{ . }}
        {{- end }}
        resources:
          requests:
            storage: {{ $p.persistence.size }}
{{- end }}
