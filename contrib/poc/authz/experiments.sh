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
experiment=${2:?outage, restart, rebuild or recreate required}
case "$profile" in authz-openfga|authz-rbac) ;; *) echo 'intent profile required' >&2; exit 2;; esac
context="kind-platform-mesh-$profile"
out="contrib/poc/authz/results/$profile-$experiment"
bash contrib/poc/authz/evidence.sh "$profile" "$out"
revision=$(git describe --always --dirty)
server=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
base=${server%%/clusters/*}
runtime() { env -u KUBECONFIG kubectl --context "$context" -n platform-mesh-system "$@"; }
kcp() { local scope=$1; shift; kubectl --server="$base/clusters/$scope" "$@"; }
probe() {
  local id=$1 state=$2 allowed=$3 reason=${4:-}
  local account=${probe_account:-org-a} parent=${probe_parent:-root:orgs}
  mkdir -p "$out/$id"
  cat > "$out/$id/cases.json" <<JSON
[{"id":"$id","parent":"$parent","account":"$account","user":"experiment-reader","grantName":"experiment-reader","state":"$state","role":"account-reader","propagation":"Local","expectedAllowed":$allowed,"expectedReason":"$reason"}]
JSON
  go run ./operators/security-operator authz-validate --profile="$profile" --revision="$revision" \
    --kcp-kubeconfig="$KUBECONFIG" --cases="$out/$id/cases.json" --output="$out/$id"
}
restore() { :; }
trap restore EXIT
case "$experiment" in
  outage)
    [ "$profile" = authz-openfga ] || { echo 'outage requires OpenFGA' >&2; exit 2; }
    probe healthy Active true
    restore() { runtime scale deployment/openfga --replicas=1 >/dev/null; }
    runtime scale deployment/openfga --replicas=0
    runtime rollout status deployment/openfga --timeout=180s
    probe backend-offline Active false
    # Administrator/system access is recorded separately from ordinary access.
    kcp root:orgs get account org-a -o name > "$out/system-access.txt"
    restore
    runtime rollout status deployment/openfga --timeout=180s
    probe recovered Active true
    ;;
  restart)
    probe healthy Active true
    restore() { runtime scale deployment/authz-controller --replicas=1 >/dev/null; }
    runtime scale deployment/authz-controller --replicas=0
    runtime rollout status deployment/authz-controller --timeout=180s
    probe projection-pending Revoked true Pending
    restore
    runtime rollout status deployment/authz-controller --timeout=180s
    probe projection-recovered Revoked false
    ;;
  rebuild)
    [ "$profile" = authz-openfga ] || { echo 'rebuild requires OpenFGA' >&2; exit 2; }
    probe healthy Active true
    # Switch to a new empty store in the same engine and replay persisted intent.
    # These arguments contain paths/options only, never credential contents.
    runtime get deployment authz-controller -o jsonpath='{.spec.template.spec.containers[0].args}' > "$out/projector-args.json"
    runtime get deployment rebac-authz-webhook -o jsonpath='{.spec.template.spec.containers[0].args}' > "$out/webhook-args.json"
    restore() {
      python3 - "$out" <<'PY' > "$out/restore-projector.json"
import json,sys
from pathlib import Path
p=Path(sys.argv[1]);print(json.dumps([dict(op='replace',path='/spec/template/spec/containers/0/args',value=json.loads((p/'projector-args.json').read_text()))]))
PY
      runtime patch deployment authz-controller --type=json --patch-file="$out/restore-projector.json" >/dev/null
      python3 - "$out" <<'PY' > "$out/restore-webhook.json"
import json,sys
from pathlib import Path
p=Path(sys.argv[1]);print(json.dumps([dict(op='replace',path='/spec/template/spec/containers/0/args',value=json.loads((p/'webhook-args.json').read_text()))]))
PY
      runtime patch deployment rebac-authz-webhook --type=json --patch-file="$out/restore-webhook.json" >/dev/null
    }
    fresh="platform-mesh-authz-poc-rebuild-$(date +%s)"
    for deployment in authz-controller rebac-authz-webhook; do
      runtime patch deployment "$deployment" --type=json \
        -p="[{\"op\":\"add\",\"path\":\"/spec/template/spec/containers/0/args/-\",\"value\":\"--store-name=$fresh\"}]"
      runtime rollout status "deployment/$deployment" --timeout=180s
    done
    probe reconstructed Active true
    ;;
  recreate)
    probe_account=disposable
    probe_parent=root:orgs:org-a
    create() {
      kcp "$probe_parent" apply -f - <<'YAML'
apiVersion: core.platform-mesh.io/v1alpha1
kind: Account
metadata:
  name: disposable
spec:
  type: account
  displayName: disposable
  creator: creator
YAML
      kcp "$probe_parent" wait account/disposable --for=condition=Ready --timeout=180s
    }
    create
    kcp "$probe_parent" get account disposable -o jsonpath='{.metadata.uid}' > "$out/original-uid.txt"
    probe original-account Active true
    kcp "$probe_parent" delete account disposable --wait=true --timeout=180s
    create
    kcp "$probe_parent" get account disposable -o jsonpath='{.metadata.uid}' > "$out/recreated-uid.txt"
    if cmp -s "$out/original-uid.txt" "$out/recreated-uid.txt"; then echo 'account UID did not change' >&2; exit 1; fi
    # No new grant: the previous user's permission must not return.
    mkdir -p "$out/recreated"
    echo '[{"id":"recreated-account-isolation","parent":"root:orgs:org-a","account":"disposable","user":"experiment-reader","expectedAllowed":false}]' > "$out/recreated/cases.json"
    go run ./operators/security-operator authz-validate --profile="$profile" --revision="$revision" --kcp-kubeconfig="$KUBECONFIG" --cases="$out/recreated/cases.json" --output="$out/recreated"
    ;;
  *) echo 'unknown experiment' >&2; exit 2;;
esac
