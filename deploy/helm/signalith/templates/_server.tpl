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
        # group-readable), and makes its data folder. Each goes in a folder
        # of Signalith's own: the volumes' top folders belong to root, and
        # some storage makes them writable by everyone.
        - name: prepare
          image: {{ include "signalith.image" $ctx }}
          imagePullPolicy: {{ $v.image.pullPolicy }}
          command:
            - sh
            - -ec
            - |
              umask 077
              copy() {
                mkdir -p "$2"
                for f in "$1"/*; do [ -f "$f" ] && install -m 0400 "$f" "$2/"; done
                return 0
              }
              copy /in/secrets /run/signalith/secrets
              if [ -d /in/opensearch ]; then copy /in/opensearch /run/signalith/opensearch; fi
              if [ -d /in/tls ]; then copy /in/tls /run/signalith/tls; fi
              mkdir -p /var/lib/signalith/data/detections /var/lib/signalith/data/lookups /var/lib/signalith/data/dashboards /var/lib/signalith/data/archive
              chmod 700 /var/lib/signalith/data
          securityContext:
            {{- include "signalith.containerSecurity" $ctx | nindent 12 }}
          resources:
            requests: { cpu: 10m, memory: 16Mi }
            limits: { memory: 64Mi }
          volumeMounts:
            - { name: secrets-in, mountPath: /in/secrets, readOnly: true }
            {{- if not $v.opensearch.enabled }}
            - { name: opensearch-in, mountPath: /in/opensearch, readOnly: true }
            {{- end }}
            {{- if $v.server.tls.existingSecret }}
            - { name: tls-in, mountPath: /in/tls, readOnly: true }
            {{- end }}
            - { name: run, mountPath: /run/signalith }
            - { name: data, mountPath: /var/lib/signalith }
      containers:
        - name: signalith
          image: {{ include "signalith.image" $ctx }}
          imagePullPolicy: {{ $v.image.pullPolicy }}
          # Without the first password, once deleted from the Secret after
          # it was changed (docs/kubernetes.md), the admin's password is
          # the one the servers share.
          command:
            - sh
            - -c
            - |
              [ -f "$SIGNALITH_ADMIN_PASSWORD_FILE" ] || unset SIGNALITH_ADMIN_PASSWORD_FILE
              exec signalith serve -c /etc/signalith/signalith.yaml
          env:
            - name: POD_NAME
              valueFrom: { fieldRef: { fieldPath: metadata.name } }
            # This server's name on the Servers page, and the address the
            # other servers reach it at.
            - name: SIGNALITH_NODE_NAME
              value: "$(POD_NAME)"
            - name: SIGNALITH_NODE_URL
              value: "https://$(POD_NAME).{{ $full }}-pods.{{ $ctx.Release.Namespace }}.svc:{{ $port }}"
            # Its folders, in the folder prepare made on the volume.
            - name: SIGNALITH_STATE_DIR
              value: /var/lib/signalith/data
            - name: SIGNALITH_DETECTIONS_DIR
              value: /var/lib/signalith/data/detections
            - name: SIGNALITH_LOOKUPS_DIR
              value: /var/lib/signalith/data/lookups
            - name: SIGNALITH_DASHBOARDS_DIR
              value: /var/lib/signalith/data/dashboards
            - name: SIGNALITH_ARCHIVE_DIR
              value: /var/lib/signalith/data/archive
            - name: SIGNALITH_ADMIN_PASSWORD_FILE
              value: /run/signalith/secrets/initial-admin-password
            - name: SIGNALITH_INGEST_TOKEN_FILE
              value: /run/signalith/secrets/ingest-token
            - name: SIGNALITH_CLUSTER_KEY_FILE
              value: /run/signalith/secrets/cluster-key
            {{- $own := default dict (get (default dict $v.server.config) "syslog") }}
            {{- if and (eq $role "server") (not (or (hasKey $own "udp") (hasKey $own "tcp"))) }}
            # Plain syslog follows server.syslog.plain, so it matches the
            # syslog Service; the Settings page shows it locked. Addresses
            # of your own in server.config.syslog are used instead.
            {{- $plain := ternary "0.0.0.0:5514" "off" (include "signalith.plainSyslog" $ctx | eq "true") }}
            - name: SIGNALITH_SYSLOG_UDP
              value: {{ $plain | quote }}
            - name: SIGNALITH_SYSLOG_TCP
              value: {{ $plain | quote }}
            {{- end }}
            {{- if and (not $v.opensearch.enabled) (eq $v.opensearch.external.auth "password") }}
            - name: SIGNALITH_OPENSEARCH_USERNAME
              valueFrom: { secretKeyRef: { name: {{ $v.opensearch.external.existingSecret }}, key: username } }
            - name: SIGNALITH_OPENSEARCH_PASSWORD_FILE
              value: /run/signalith/opensearch/password
            {{- end }}
            {{- with $p.extraEnv }}
            {{- toYaml . | nindent 12 }}
            {{- end }}
          ports:
            - { name: https, containerPort: {{ $port }}, protocol: TCP }
            - { name: agents, containerPort: {{ include "signalith.agentPort" $ctx }}, protocol: TCP }
            {{- if and $v.server.syslog.enabled (eq $role "server") }}
            {{- if include "signalith.plainSyslog" $ctx }}
            - { name: syslog-udp, containerPort: 5514, protocol: UDP }
            - { name: syslog-tcp, containerPort: 5514, protocol: TCP }
            {{- end }}
            - { name: syslog-tls, containerPort: 6514, protocol: TCP }
            {{- end }}
          # /readyz and /livez answer on plain HTTP too (docs/servers.md,
          # Load balancers). A server waiting for OpenSearch is not ready,
          # but restarting it would not help, so only /livez restarts it.
          startupProbe:
            httpGet: { path: /livez, port: https, scheme: HTTP }
            periodSeconds: 5
            timeoutSeconds: 5
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
            - { name: run, mountPath: /run/signalith, readOnly: true }
            - { name: tmp, mountPath: /tmp }
      volumes:
        - name: config
          configMap: { name: {{ $full }}-config }
        - name: secrets-in
          secret:
            secretName: {{ include "signalith.secretsName" $ctx }}
            defaultMode: 0440
        # Memory only: the copies of the secrets.
        - name: run
          emptyDir: { medium: Memory, sizeLimit: 4Mi }
        {{- if not $v.opensearch.enabled }}
        - name: opensearch-in
          secret:
            secretName: {{ required "opensearch.external.existingSecret is required when opensearch.enabled is false" $v.opensearch.external.existingSecret }}
            defaultMode: 0440
        {{- end }}
        {{- if $v.server.tls.existingSecret }}
        - name: tls-in
          secret:
            secretName: {{ $v.server.tls.existingSecret }}
            defaultMode: 0440
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
