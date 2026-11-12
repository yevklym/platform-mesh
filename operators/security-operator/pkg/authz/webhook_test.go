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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	fga "github.com/openfga/api/proto/openfga/v1"
	"google.golang.org/grpc"

	authorizationv1 "k8s.io/api/authorization/v1"
)

type webhookFGA struct {
	fga.OpenFGAServiceClient
	check func(*fga.CheckRequest) (*fga.CheckResponse, error)
}

func (f webhookFGA) Check(_ context.Context, request *fga.CheckRequest, _ ...grpc.CallOption) (*fga.CheckResponse, error) {
	return f.check(request)
}

func TestWebhookDiscovery(t *testing.T) {
	for _, test := range []struct {
		name        string
		path        string
		verb        string
		clusters    []string
		revoked     bool
		backendDown bool
		wantCheck   bool
		wantAllowed bool
		wantDenied  bool
	}{
		{name: "API groups", path: "/apis", wantCheck: true, wantAllowed: true},
		{name: "group discovery", path: "/apis/core.platform-mesh.io/v1alpha1", wantCheck: true, wantAllowed: true},
		{name: "core discovery", path: "/api", wantCheck: true, wantAllowed: true},
		{name: "core version discovery", path: "/api/v1", wantCheck: true, wantAllowed: true},
		{name: "OpenAPI", path: "/openapi/v2", wantCheck: true, wantAllowed: true},
		{name: "OpenAPI v3", path: "/openapi/v3/apis/core.platform-mesh.io/v1alpha1", wantCheck: true, wantAllowed: true},
		{name: "server version", path: "/version", wantCheck: true, wantAllowed: true},
		{name: "revoked reader", path: "/apis", revoked: true, wantCheck: true},
		{name: "different workspace", path: "/apis", clusters: []string{"other"}, wantCheck: true},
		{name: "missing scope", path: "/apis", clusters: []string{}},
		{name: "ambiguous scope", path: "/apis", clusters: []string{"target", "other"}},
		{name: "backend down", path: "/apis", backendDown: true, wantCheck: true, wantDenied: true},
		{name: "discovery write", path: "/apis", verb: "post"},
		{name: "metrics", path: "/metrics"},
		{name: "debug", path: "/debug/pprof"},
		{name: "prefix collision", path: "/apisecrets"},
	} {
		t.Run(test.name, func(t *testing.T) {
			clusters := test.clusters
			if clusters == nil {
				clusters = []string{"target"}
			}
			verb := test.verb
			if verb == "" {
				verb = "get"
			}
			checks := 0
			backend := &FGA{StoreID: "store", ModelID: "model", Client: webhookFGA{check: func(request *fga.CheckRequest) (*fga.CheckResponse, error) {
				checks++
				if request.StoreId != "store" || request.AuthorizationModelId != "model" || request.TupleKey.User != userKey("reader") || request.TupleKey.Object != workspaceKey(clusters[0]) || request.TupleKey.Relation != "reader" {
					t.Fatalf("discovery check used the wrong identity, scope or permission: %v", request)
				}
				if test.backendDown {
					return nil, fmt.Errorf("offline")
				}
				return &fga.CheckResponse{Allowed: !test.revoked && clusters[0] == "target"}, nil
			}}}
			review := authorizationv1.SubjectAccessReview{Spec: authorizationv1.SubjectAccessReviewSpec{
				User:                  "reader",
				Groups:                []string{"system:authenticated"},
				Extra:                 map[string]authorizationv1.ExtraValue{"authorization.kcp.io/cluster-name": clusters},
				NonResourceAttributes: &authorizationv1.NonResourceAttributes{Verb: verb, Path: test.path},
			}}
			body, err := json.Marshal(review)
			if err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			backend.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/authz", bytes.NewReader(body)))
			var result authorizationv1.SubjectAccessReview
			if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if result.Status.Allowed != test.wantAllowed || result.Status.Denied != test.wantDenied {
				t.Fatalf("got status %+v; want allowed=%t denied=%t", result.Status, test.wantAllowed, test.wantDenied)
			}
			if (checks > 0) != test.wantCheck {
				t.Fatalf("got %d backend checks; want check=%t", checks, test.wantCheck)
			}
		})
	}
}
