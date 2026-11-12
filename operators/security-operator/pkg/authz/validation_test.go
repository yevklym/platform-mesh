/*
Copyright The Platform Mesh Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package authz

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReportRetainsFailures(t *testing.T) {
	directory := t.TempDir()
	report := ValidationReport{Profile: "authz-rbac", Revision: "test-dirty", Results: []ValidationResult{{ID: "projection", Classification: "defect", Reason: "backend unavailable"}, {ID: "inheritance", Classification: "unsupported"}}}
	if err := WriteReport(directory, report); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(directory, "results.json"))
	if err != nil {
		t.Fatal(err)
	}
	var got ValidationReport
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.Results[0].Classification != "defect" {
		t.Fatal("failure was hidden")
	}
	junit, err := os.ReadFile(filepath.Join(directory, "junit.xml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(junit), "<failure>backend unavailable</failure>") {
		t.Fatal("JUnit failure omitted")
	}
}
