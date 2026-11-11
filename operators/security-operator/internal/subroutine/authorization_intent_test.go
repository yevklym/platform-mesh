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

package subroutine_test

import (
	"context"
	"fmt"
	"testing"

	pmcorev1alpha1 "go.platform-mesh.io/apis/core/v1alpha1"
	"go.platform-mesh.io/security-operator/internal/subroutine"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrlruntimeclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	kcpcorev1alpha1 "github.com/kcp-dev/sdk/apis/core/v1alpha1"
)

type intentClients struct{ ctrlruntimeclient.Client }

func (c intentClients) NewClientForLogicalCluster(_ context.Context, cluster string) (ctrlruntimeclient.Client, error) {
	if cluster != "parent" {
		return nil, fmt.Errorf("wrong parent %s", cluster)
	}
	return c.Client, nil
}
func (c intentClients) NewClientFromContext(context.Context) (ctrlruntimeclient.Client, error) {
	return c.Client, nil
}
func TestIntentDoesNotRestoreRevokedCreatorGrant(t *testing.T) {
	ctx := context.Background()
	s := runtime.NewScheme()
	_ = pmcorev1alpha1.AddToScheme(s)
	creator := "creator"
	account := &pmcorev1alpha1.Account{ObjectMeta: metav1.ObjectMeta{Name: "a", UID: "account"}, Spec: pmcorev1alpha1.AccountSpec{Creator: &creator}}
	c := fake.NewClientBuilder().WithScheme(s).WithStatusSubresource(&pmcorev1alpha1.AuthorizationGrant{}).WithObjects(account).Build()
	lc := &kcpcorev1alpha1.LogicalCluster{Spec: kcpcorev1alpha1.LogicalClusterSpec{Owner: &kcpcorev1alpha1.LogicalClusterOwner{}}}
	lc.Spec.Owner.Cluster = "parent"
	lc.Spec.Owner.Name = "a"
	sub := &subroutine.AuthorizationIntent{Clients: intentClients{c}}
	if _, err := sub.Process(ctx, lc); err != nil {
		t.Fatal(err)
	}
	var g pmcorev1alpha1.AuthorizationGrant
	if err := c.Get(ctx, ctrlruntimeclient.ObjectKey{Name: "bootstrap-account"}, &g); err != nil {
		t.Fatal(err)
	}
	g.Spec.State = "Revoked"
	g.Generation = 1
	if err := c.Update(ctx, &g); err != nil {
		t.Fatal(err)
	}
	meta.SetStatusCondition(&g.Status.Conditions, metav1.Condition{Type: "Reconciled", Status: metav1.ConditionTrue, Reason: "Reconciled", ObservedGeneration: 1})
	g.Status.ObservedGeneration = 1
	if err := c.Status().Update(ctx, &g); err != nil {
		t.Fatal(err)
	}
	// A fresh core instance sees the retained intent rather than restoring access.
	sub = &subroutine.AuthorizationIntent{Clients: intentClients{c}}
	if _, err := sub.Process(ctx, lc); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, ctrlruntimeclient.ObjectKey{Name: g.Name}, &g); err != nil {
		t.Fatal(err)
	}
	if g.Spec.State != "Revoked" {
		t.Fatal("creator access resurrected")
	}
	if err := c.Get(ctx, ctrlruntimeclient.ObjectKey{Name: "a"}, account); err != nil {
		t.Fatal(err)
	}
	if account.Annotations["authz.platform-mesh.io/bootstrap-created"] != "true" {
		t.Fatal("initialization did not settle revoked desired state")
	}
}
