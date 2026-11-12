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

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class FixturePublicationTests(unittest.TestCase):
    def test_missing_provider_api_stops_before_account_provisioning(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "kubectl"
            executable.write_text("""#!/usr/bin/env python3
import json, os, sys
with open(os.environ['POC_COMMAND_LOG'], 'a') as log:
    log.write(json.dumps(sys.argv[1:]) + '\\n')
if sys.argv[1:3] == ['config', 'view']:
    print('https://example.invalid/clusters/root')
if 'apiexport/orchestrate.platform-mesh.io' in sys.argv and 'wait' in sys.argv:
    sys.exit(1)
""")
            executable.chmod(0o755)
            command_log = root / "commands.jsonl"
            environment = dict(os.environ, PATH=str(root) + os.pathsep + os.environ['PATH'],
                               KUBECONFIG=str(root / "admin.kubeconfig"), POC_COMMAND_LOG=str(command_log))
            result = subprocess.run(['bash', str(Path(__file__).with_name('fixtures.sh'))],
                                    env=environment, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0, result.stdout)
            commands = [json.loads(line) for line in command_log.read_text().splitlines()]
            self.assertTrue(any('apiexport/orchestrate.platform-mesh.io' in command for command in commands))
            self.assertFalse(any(any(arg.startswith('accounts/') for arg in command) for command in commands))
