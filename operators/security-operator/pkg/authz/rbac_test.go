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
	"testing"

	pmcorev1alpha1 "go.platform-mesh.io/apis/core/v1alpha1"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestRBACOwnershipAndRevocation(t *testing.T) {
	s := runtime.NewScheme()
	_ = rbacv1.AddToScheme(s)
	c := fake.NewClientBuilder().WithScheme(s).Build()
	b := RBAC{Client: c}
	ctx := context.Background()
	a := pmcorev1alpha1.AuthorizationGrant{ObjectMeta: metav1.ObjectMeta{UID: types.UID("a")}, Spec: pmcorev1alpha1.AuthorizationGrantSpec{Subject: pmcorev1alpha1.GrantSubject{Kind: "User", Name: "alice"}, RoleRef: "account-reader", Propagation: "Local", State: "Active"}}
	z := *a.DeepCopy()
	z.UID = "b"
	for _, g := range []*pmcorev1alpha1.AuthorizationGrant{&a, &z} {
		if err := b.Apply(ctx, g); err != nil {
			t.Fatal(err)
		}
	}
	a.Spec.State = "Revoked"
	if err := b.Apply(ctx, &a); err != nil {
		t.Fatal(err)
	}
	var bindings rbacv1.ClusterRoleBindingList
	if err := c.List(ctx, &bindings); err != nil {
		t.Fatal(err)
	}
	if len(bindings.Items) != 1 || bindings.Items[0].Subjects[0].Name != "alice" {
		t.Fatalf("surviving grant lost: %#v", bindings.Items)
	}
	z.Spec.State = "Revoked"
	if err := b.Apply(ctx, &z); err != nil {
		t.Fatal(err)
	}
	_ = c.List(ctx, &bindings)
	if len(bindings.Items) != 0 {
		t.Fatal("revocation left access")
	}
}

func TestRBACRejectsUnsupportedBeforeWriting(t *testing.T) {
	s := runtime.NewScheme()
	_ = rbacv1.AddToScheme(s)
	c := fake.NewClientBuilder().WithScheme(s).Build()
	g := pmcorev1alpha1.AuthorizationGrant{ObjectMeta: metav1.ObjectMeta{UID: "x"}, Spec: pmcorev1alpha1.AuthorizationGrantSpec{Subject: pmcorev1alpha1.GrantSubject{Kind: "User", Name: "alice"}, RoleRef: "account-editor", Propagation: "Descendants", State: "Active"}}
	if err := (&RBAC{Client: c}).Apply(context.Background(), &g); err == nil {
		t.Fatal("accepted inheritance")
	}
	var list rbacv1.ClusterRoleBindingList
	_ = c.List(context.Background(), &list)
	if len(list.Items) != 0 {
		t.Fatal("partial projection")
	}
}

func TestEditorCannotManageAuthorization(t *testing.T) {
	rules, err := Rules("account-editor")
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range rules {
		for _, resource := range rule.Resources {
			if resource != "httpbins" && len(rule.Verbs) > 3 {
				t.Fatalf("unexpected write authority: %#v", rule)
			}
		}
	}
}
