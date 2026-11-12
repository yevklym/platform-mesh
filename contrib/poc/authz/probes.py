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

# Shared by the Tilt profile and offline regression tests. Keep Starlark compatible.
def configure_authz_probes(container):
    """Point every probe at the authz command's explicit health listener."""
    container["args"].append("--health-probe-bind-address=:8090")
    for name, path in [("startupProbe", "/healthz"), ("livenessProbe", "/healthz"), ("readinessProbe", "/readyz")]:
        container[name] = {
            "httpGet": {"path": path, "port": 8090},
            "periodSeconds": 5,
            "timeoutSeconds": 2,
            "failureThreshold": 6,
        }
    container["startupProbe"]["failureThreshold"] = 30
