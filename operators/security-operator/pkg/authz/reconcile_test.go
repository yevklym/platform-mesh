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
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	fga "github.com/openfga/api/proto/openfga/v1"
	language "github.com/openfga/language/pkg/go/transformer"
	"google.golang.org/grpc"

	pmcorev1alpha1 "go.platform-mesh.io/apis/core/v1alpha1"

	authorizationv1 "k8s.io/api/authorization/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrlruntimeclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	kcptenancyv1alpha1 "github.com/kcp-dev/sdk/apis/tenancy/v1alpha1"
)

func TestReconcileLifecycle(t *testing.T) {
	ctx := context.Background()
	s := runtime.NewScheme()
	_ = pmcorev1alpha1.AddToScheme(s)
	_ = kcptenancyv1alpha1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)
	g := &pmcorev1alpha1.AuthorizationGrant{ObjectMeta: metav1.ObjectMeta{Name: "g", UID: "grant", Generation: 1}, Spec: pmcorev1alpha1.AuthorizationGrantSpec{AccountRef: pmcorev1alpha1.GrantAccountReference{Name: "a", UID: "account"}, Subject: pmcorev1alpha1.GrantSubject{Kind: "User", Name: "alice"}, RoleRef: "account-editor", Propagation: "Local", State: "Active"}}
	a := &pmcorev1alpha1.Account{ObjectMeta: metav1.ObjectMeta{Name: "a", UID: "account"}}
	ws := &kcptenancyv1alpha1.Workspace{ObjectMeta: metav1.ObjectMeta{Name: "a"}, Spec: kcptenancyv1alpha1.WorkspaceSpec{Cluster: "target"}}
	source := fake.NewClientBuilder().WithScheme(s).WithStatusSubresource(g).WithObjects(g, a, ws).Build()
	target := fake.NewClientBuilder().WithScheme(s).Build()
	r := Reconciler{Backend: "rbac", ClientFor: func(name string) (ctrlruntimeclient.Client, error) {
		if name != "target" {
			t.Fatalf("wrong target %s", name)
		}
		return target, nil
	}}
	for range 4 {
		if err := source.Get(ctx, ctrlruntimeclient.ObjectKey{Name: "g"}, g); err != nil {
			t.Fatal(err)
		}
		if err := r.Reconcile(ctx, source, g); err != nil {
			t.Fatal(err)
		}
	}
	if err := source.Get(ctx, ctrlruntimeclient.ObjectKey{Name: "g"}, g); err != nil {
		t.Fatal(err)
	}
	if !meta.IsStatusConditionTrue(g.Status.Conditions, "Reconciled") {
		t.Fatal("projection not observed")
	}
	g.Spec.State = "Revoked"
	g.Generation = 2
	if err := source.Update(ctx, g); err != nil {
		t.Fatal(err)
	}
	if err := r.Reconcile(ctx, source, g); err != nil {
		t.Fatal(err)
	}
	var bindings rbacv1.ClusterRoleBindingList
	_ = target.List(ctx, &bindings)
	if len(bindings.Items) != 0 {
		t.Fatal("revocation retained effective bindings")
	}
	// A stale grant must never authorize a replacement Account with the same name.
	a.UID = "new-account"
	if err := source.Update(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := source.Get(ctx, ctrlruntimeclient.ObjectKey{Name: "g"}, g); err != nil {
		t.Fatal(err)
	}
	if err := r.Reconcile(ctx, source, g); err == nil {
		t.Fatal("accepted stale account UID")
	}
}

type failingFGA struct{ fga.OpenFGAServiceClient }

func (failingFGA) Check(context.Context, *fga.CheckRequest, ...grpc.CallOption) (*fga.CheckResponse, error) {
	return nil, fmt.Errorf("offline")
}
func TestWebhookFailsClosed(t *testing.T) {
	b := &FGA{Client: failingFGA{}}
	req := httptest.NewRequest(http.MethodPost, "/authz", strings.NewReader(`{"apiVersion":"authorization.k8s.io/v1","kind":"SubjectAccessReview","spec":{"user":"alice","extra":{"authorization.kcp.io/cluster-name":["target"]},"resourceAttributes":{"group":"orchestrate.platform-mesh.io","resource":"httpbins","verb":"get"}}}`))
	out := httptest.NewRecorder()
	b.Handler().ServeHTTP(out, req)
	var review authorizationv1.SubjectAccessReview
	if err := json.Unmarshal(out.Body.Bytes(), &review); err != nil {
		t.Fatal(err)
	}
	if review.Status.Allowed || !review.Status.Denied {
		t.Fatal("backend error did not deny managed request")
	}
}
func TestModelAndIdentityEncoding(t *testing.T) {
	if _, err := language.TransformDSLToProto(Model); err != nil {
		t.Fatal(err)
	}
	if userKey("a:b") == userKey("a.b") {
		t.Fatal("identity collision")
	}
	for _, a := range []authorizationv1.ResourceAttributes{{Group: "rbac.authorization.k8s.io", Resource: "clusterrolebindings", Verb: "create"}, {Group: "core.platform-mesh.io", Resource: "accounts", Verb: "create"}, {Group: "orchestrate.platform-mesh.io", Resource: "httpbins", Subresource: "status", Verb: "update"}} {
		if _, ok := RequiredRole(&a); ok {
			t.Fatalf("unexpected management authority: %#v", a)
		}
	}
}

func TestReconcileReportsUnsupportedInheritance(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pmcorev1alpha1.AddToScheme(scheme)
	_ = kcptenancyv1alpha1.AddToScheme(scheme)
	_ = rbacv1.AddToScheme(scheme)
	grant := &pmcorev1alpha1.AuthorizationGrant{
		ObjectMeta: metav1.ObjectMeta{Name: "inherited", UID: "grant", Generation: 1, Finalizers: []string{Finalizer}, OwnerReferences: []metav1.OwnerReference{{APIVersion: pmcorev1alpha1.SchemeGroupVersion.String(), Kind: "Account", Name: "account", UID: "account"}}},
		Spec:       pmcorev1alpha1.AuthorizationGrantSpec{AccountRef: pmcorev1alpha1.GrantAccountReference{Name: "account", UID: "account"}, Subject: pmcorev1alpha1.GrantSubject{Kind: "User", Name: "reader"}, RoleRef: "account-reader", Propagation: "Descendants", State: "Active"},
		Status:     pmcorev1alpha1.AuthorizationGrantStatus{Workspace: "target"},
	}
	source := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(grant).WithObjects(grant, &pmcorev1alpha1.Account{ObjectMeta: metav1.ObjectMeta{Name: "account", UID: "account"}}, &kcptenancyv1alpha1.Workspace{ObjectMeta: metav1.ObjectMeta{Name: "account"}, Spec: kcptenancyv1alpha1.WorkspaceSpec{Cluster: "target"}}).Build()
	target := fake.NewClientBuilder().WithScheme(scheme).Build()
	reconciler := Reconciler{Backend: "rbac", ClientFor: func(name string) (ctrlruntimeclient.Client, error) {
		if name == "target" {
			return target, nil
		}
		return source, nil
	}}
	if err := reconciler.Reconcile(ctx, source, grant); err == nil {
		t.Fatal("unsupported capability error was discarded")
	}
	if err := source.Get(ctx, ctrlruntimeclient.ObjectKey{Name: grant.Name}, grant); err != nil {
		t.Fatal(err)
	}
	condition := meta.FindStatusCondition(grant.Status.Conditions, "Reconciled")
	if condition == nil || condition.Status != metav1.ConditionFalse || condition.Reason != "UnsupportedCapability" || condition.ObservedGeneration != grant.Generation {
		t.Fatalf("incorrect status: %+v", condition)
	}
	var bindings rbacv1.ClusterRoleBindingList
	if err := target.List(ctx, &bindings); err != nil {
		t.Fatal(err)
	}
	if len(bindings.Items) != 0 {
		t.Fatal("unsupported grant created permission bindings")
	}
	// A terminal capability rejection remains visible on the grant, but must
	// not be reported as an infrastructure/reconciliation failure every poll.
	if err := reconciler.Once(ctx, "parent"); err != nil {
		t.Fatalf("terminal capability rejection kept retrying: %v", err)
	}
}

type policyListErrorClient struct {
	ctrlruntimeclient.Client
	listErr error
}

func (c policyListErrorClient) List(ctx context.Context, list ctrlruntimeclient.ObjectList, opts ...ctrlruntimeclient.ListOption) error {
	if _, ok := list.(*pmcorev1alpha1.APIExportPolicyList); ok {
		return c.listErr
	}
	return c.Client.List(ctx, list, opts...)
}
func TestOptionalPolicyAPIMayBeAbsent(t *testing.T) {
	for _, test := range []struct {
		name    string
		err     error
		wantErr bool
	}{
		{"API not installed", &meta.NoKindMatchError{GroupKind: schema.GroupKind{Group: pmcorev1alpha1.GroupName, Kind: "APIExportPolicy"}}, false},
		{"API failure", fmt.Errorf("API unavailable"), true},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := runtime.NewScheme()
			_ = pmcorev1alpha1.AddToScheme(s)
			c := policyListErrorClient{Client: fake.NewClientBuilder().WithScheme(s).Build(), listErr: test.err}
			r := Reconciler{ClientFor: func(string) (ctrlruntimeclient.Client, error) { return c, nil }}
			if err := r.Once(context.Background(), "account-workspace"); (err != nil) != test.wantErr {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
