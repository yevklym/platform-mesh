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
: "${KUBECONFIG:?PoC administrator kubeconfig required}"
server=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
base=${server%%/clusters/*}
# Only runner-created grants are removed. Bootstrap and administrator grants have
# independent lifetimes. Projection finalizers must finish before a new run.
kubectl --server="$base/clusters/root:orgs" delete authorizationgrants \
  -l authz.platform-mesh.io/validation=true --wait=true --timeout=180s
