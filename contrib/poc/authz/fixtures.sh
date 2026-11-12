#!/usr/bin/env bash

# Copyright The Platform Mesh Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -euo pipefail
: "${KUBECONFIG:?point KUBECONFIG to the dedicated PoC administrator kubeconfig}"
server=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
base=${server%%/clusters/*}
k() { local workspace=$1; shift; kubectl --server="$base/clusters/$workspace" "$@"; }
account() {
  local parent=$1 name=$2 kind=$3
  k "$parent" apply -f - <<YAML
apiVersion: core.platform-mesh.io/v1alpha1
kind: Account
metadata:
  name: $name
spec:
  type: $kind
  displayName: $name
  creator: creator
YAML
  k "$parent" wait "accounts/$name" --for=condition=Ready --timeout=180s
}
# A Bound APIBinding can refer to an empty export. Require the actual provider
# resource before provisioning accounts or interpreting permission results.
k root:providers:httpbin-provider wait apiexport/orchestrate.platform-mesh.io \
  '--for=jsonpath={.spec.resources[?(@.name=="httpbins")].schema}' --timeout=180s

account root:orgs org-a org
account root:orgs org-b org
account root:orgs:org-a account-a account
account root:orgs:org-a:account-a nested account
# The platform's default HTTPBin binding applies to account workspaces only.
# Portable-role probes also run in organization workspaces, so bind explicitly
# and wait for the API to be served before checking authorization there.
for workspace in root:orgs:org-a root:orgs:org-b; do
  k "$workspace" apply -f - <<'YAML'
apiVersion: apis.kcp.io/v1alpha2
kind: APIBinding
metadata:
  name: authz-poc-httpbin
spec:
  reference:
    export:
      path: root:providers:httpbin-provider
      name: orchestrate.platform-mesh.io
YAML
  k "$workspace" wait apibinding/authz-poc-httpbin '--for=jsonpath={.status.phase}=Bound' --timeout=180s
done
for workspace in root:orgs:org-a root:orgs:org-b root:orgs:org-a:account-a root:orgs:org-a:account-a:nested; do
  k "$workspace" create namespace poc --dry-run=client -o yaml | k "$workspace" apply -f -
  # Review creation must work even for a user whose resource access was revoked.
  # This rule grants no permission on the resource being reviewed.
  k "$workspace" apply -f - <<'YAML'
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: authz-poc-access-reviews
rules:
- apiGroups: [authorization.k8s.io]
  resources: [selfsubjectaccessreviews]
  verbs: [create]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: authz-poc-access-reviews
subjects:
- kind: Group
  name: system:authenticated
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: authz-poc-access-reviews
  apiGroup: rbac.authorization.k8s.io
YAML
 done
