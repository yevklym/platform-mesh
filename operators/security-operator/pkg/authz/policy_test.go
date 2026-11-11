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
	ctrlruntimeclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	kcpcorev1alpha1 "github.com/kcp-dev/sdk/apis/core/v1alpha1"
)

func TestPolicyPartialProjectionHasCleanupOwnership(t *testing.T) {
	ctx := context.Background()
	s := runtime.NewScheme()
	_ = pmcorev1alpha1.AddToScheme(s)
	_ = kcpcorev1alpha1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)
	policy := &pmcorev1alpha1.APIExportPolicy{ObjectMeta: metav1.ObjectMeta{Name: "provider", UID: "policy"}, Spec: pmcorev1alpha1.APIExportPolicySpec{APIExportRef: pmcorev1alpha1.APIExportRef{ClusterPath: "provider", Name: "export"}, AllowPathExpressions: []string{":root:orgs:ready", ":root:orgs:pending"}}}
	source := fake.NewClientBuilder().WithScheme(s).WithStatusSubresource(policy).WithObjects(policy).Build()
	provider := fake.NewClientBuilder().WithScheme(s).Build()
	ready := fake.NewClientBuilder().WithScheme(s).WithObjects(&kcpcorev1alpha1.LogicalCluster{ObjectMeta: metav1.ObjectMeta{Name: "cluster", Annotations: map[string]string{"kcp.io/cluster": "consumer"}}}).Build()
	pending := fake.NewClientBuilder().WithScheme(s).Build()
	r := Reconciler{Backend: "rbac", ClientFor: func(name string) (ctrlruntimeclient.Client, error) {
		if name == "provider" {
			return provider, nil
		}
		if name == "root:orgs:ready" {
			return ready, nil
		}
		return pending, nil
	}}
	// One consumer is still absent after the first has received binding eligibility.
	for range 4 {
		if err := source.Get(ctx, ctrlruntimeclient.ObjectKey{Name: policy.Name}, policy); err != nil {
			t.Fatal(err)
		}
		_ = r.Policy(ctx, source, policy)
	}
	var bindings rbacv1.ClusterRoleBindingList
	_ = provider.List(ctx, &bindings)
	if len(bindings.Items) != 1 {
		t.Fatal("first consumer was not projected")
	}
	if len(policy.Status.ManagedAllowExpressions) != 2 {
		t.Fatal("partial writes were not reserved for cleanup")
	}
	if err := source.Delete(ctx, policy); err != nil {
		t.Fatal(err)
	}
	if err := source.Get(ctx, ctrlruntimeclient.ObjectKey{Name: policy.Name}, policy); err != nil {
		t.Fatal(err)
	}
	if err := r.Policy(ctx, source, policy); err != nil {
		t.Fatal(err)
	}
	_ = provider.List(ctx, &bindings)
	if len(bindings.Items) != 0 {
		t.Fatal("partial projection leaked bind permission")
	}
}
