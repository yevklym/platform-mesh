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
profile=${1:?profile required}
out=${2:?output directory required}
case "$profile" in authz-baseline|authz-openfga|authz-rbac) ;; *) exit 2;; esac
context="kind-platform-mesh-$profile"
mkdir -p "$out"
k() { env -u KUBECONFIG kubectl --context "$context" -n platform-mesh-system "$@"; }
if [ -n "${KUBECONFIG:-}" ]; then
  expected=$(k get secret kubeconfig-kcp-admin -o jsonpath='{.data.kubeconfig}' | base64 -d | shasum -a 256 | cut -d ' ' -f 1)
  actual=$(shasum -a 256 "$KUBECONFIG" | cut -d ' ' -f 1)
  [ "$expected" = "$actual" ] || { echo 'PoC kubeconfig belongs to another deployment; refresh the export' >&2; exit 1; }
fi
k get deployments \
  -o 'custom-columns=NAME:.metadata.name,REPLICAS:.spec.replicas,IMAGES:.spec.template.spec.containers[*].image' > "$out/components.txt"
k get pods \
  -o 'custom-columns=NAME:.metadata.name,IMAGE_IDS:.status.containerStatuses[*].imageID' > "$out/image-digests.txt"
k get rootshard root \
  -o 'jsonpath={.spec.authorization}{"\n"}{.spec.extraArgs}{"\n"}' > "$out/root-authorization.txt"
k get shard triton \
  -o 'jsonpath={.spec.authorization}{"\n"}{.spec.extraArgs}{"\n"}' > "$out/shard-authorization.txt"
git describe --always --dirty > "$out/revision.txt"
if [ "$profile" = authz-rbac ]; then
  if grep -Eq '^openfga[[:space:]]|^rebac-authz-webhook[[:space:]]' "$out/components.txt"; then
    echo 'RBAC profile still contains an OpenFGA/webhook deployment' >&2
    exit 1
  fi
  if grep -q 'configSecretName' "$out/root-authorization.txt" "$out/shard-authorization.txt"; then
    echo 'RBAC profile still registers an authorization webhook' >&2
    exit 1
  fi
fi
