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
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthDoesNotRequireFutureFixtureWorkspaces(t *testing.T) {
	health := &Health{}
	for _, test := range []struct {
		path  string
		ready bool
		want  int
	}{
		{"/healthz", false, http.StatusOK},
		{"/readyz", false, http.StatusServiceUnavailable},
		{"/readyz", true, http.StatusOK},
		{"/healthz", true, http.StatusOK},
	} {
		health.SetReady(test.ready)
		response := httptest.NewRecorder()
		health.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, test.path, nil))
		if response.Code != test.want {
			t.Errorf("%s ready=%v got %d want %d", test.path, test.ready, response.Code, test.want)
		}
	}
}
