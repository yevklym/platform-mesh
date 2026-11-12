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

import unittest

from probes import configure_authz_probes


class AuthzProbeTests(unittest.TestCase):
    def test_all_inherited_probes_match_the_explicit_listener(self):
        for mode in ["--projection-only", "--checks-only"]:
            with self.subTest(mode=mode):
                container = {
                    "args": ["authz", mode],
                    "startupProbe": {"httpGet": {"port": 8080, "path": "/legacy"}},
                    "livenessProbe": {"httpGet": {"port": 8080}},
                    "readinessProbe": {"httpGet": {"port": 8080}},
                }
                configure_authz_probes(container)
                self.assertIn("--health-probe-bind-address=:8090", container["args"])
                for name, path in [("startupProbe", "/healthz"), ("livenessProbe", "/healthz"), ("readinessProbe", "/readyz")]:
                    self.assertEqual(container[name]["httpGet"], {"port": 8090, "path": path})


if __name__ == "__main__":
    unittest.main()
