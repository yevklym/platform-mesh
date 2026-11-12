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
	"net/http"
	"strings"

	fga "github.com/openfga/api/proto/openfga/v1"

	authorizationv1 "k8s.io/api/authorization/v1"
)

// Handler is the experimental FGA webhook. It recognizes only the portable
// catalog; errors deny managed requests rather than silently falling back.
func (b *FGA) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var sar authorizationv1.SubjectAccessReview
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&sar); err != nil {
			http.Error(w, "invalid SAR", 400)
			return
		}
		attrs := sar.Spec.ResourceAttributes
		clusters := sar.Spec.Extra["authorization.kcp.io/cluster-name"]
		if len(clusters) == 0 {
			clusters = sar.Spec.Extra["authorization.kubernetes.io/cluster-name"]
		}
		if attrs != nil && len(clusters) == 1 {
			// SSAR creation is allowed for authenticated identities, while the review
			// itself still traverses kcp's authorization chain for the requested action.
			if attrs.Group == "authorization.k8s.io" && attrs.Resource == "selfsubjectaccessreviews" && attrs.Verb == "create" {
				for _, group := range sar.Spec.Groups {
					if group == "system:authenticated" {
						sar.Status.Allowed = true
					}
				}
			} else {
				if attrs.Group == "apis.kcp.io" && attrs.Resource == "apiexports" && attrs.Verb == "bind" {
					for _, group := range sar.Spec.Groups {
						if consumer, ok := strings.CutPrefix(group, "system:cluster:"); ok {
							result, err := b.Client.Check(r.Context(), &fga.CheckRequest{StoreId: b.StoreID, AuthorizationModelId: b.ModelID, TupleKey: &fga.CheckRequestTupleKey{User: workspaceKey(consumer), Object: exportKey(clusters[0], attrs.Name), Relation: "bind"}, Consistency: fga.ConsistencyPreference_HIGHER_CONSISTENCY})
							if err != nil {
								sar.Status.Denied = true
								sar.Status.Reason = "authorization backend unavailable"
							} else {
								sar.Status.Allowed = result.Allowed
							}
							break
						}
					}
				}
				role, managed := RequiredRole(attrs)
				if managed {
					allowed, err := b.Check(r.Context(), sar.Spec.User, clusters[0], role)
					sar.Status.Allowed = allowed
					if err != nil {
						sar.Status.Allowed = false
						sar.Status.Denied = true
						sar.Status.Reason = "authorization backend unavailable"
					}
				}
			}
		} else if len(clusters) == 1 && isDiscoveryRequest(sar.Spec.NonResourceAttributes) {
			// Clients discover API groups and resources before making resource
			// requests. Discovery follows reader access in this workspace.
			allowed, err := b.Check(r.Context(), sar.Spec.User, clusters[0], "reader")
			sar.Status.Allowed = allowed
			if err != nil {
				sar.Status.Allowed = false
				sar.Status.Denied = true
				sar.Status.Reason = "authorization backend unavailable"
			}
		}
		sar.Spec = authorizationv1.SubjectAccessReviewSpec{}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(sar)
	})
}

func isDiscoveryRequest(a *authorizationv1.NonResourceAttributes) bool {
	if a == nil || a.Verb != "get" {
		return false
	}
	if a.Path == "/version" || a.Path == "/version/" {
		return true
	}
	for _, prefix := range []string{"/api", "/apis", "/openapi"} {
		if a.Path == prefix || strings.HasPrefix(a.Path, prefix+"/") {
			return true
		}
	}
	return false
}

// RequiredRole matches exact resources and rejects all subresources by default.
func RequiredRole(a *authorizationv1.ResourceAttributes) (string, bool) {
	if a.Subresource != "" {
		return "", false
	}
	readable := (a.Group == "core.platform-mesh.io" && (a.Resource == "accounts" || a.Resource == "accountinfos")) || (a.Group == "orchestrate.platform-mesh.io" && a.Resource == "httpbins")
	if !readable {
		return "", false
	}
	switch a.Verb {
	case "get", "list", "watch":
		return "reader", true
	}
	if a.Group == "orchestrate.platform-mesh.io" {
		switch a.Verb {
		case "create", "update", "patch", "delete":
			return "editor", true
		}
	}
	return "", false
}
