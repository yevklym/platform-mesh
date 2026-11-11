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

package subroutine

import (
	"context"
	"fmt"
	"time"

	pmcorev1alpha1 "go.platform-mesh.io/apis/core/v1alpha1"
	iclient "go.platform-mesh.io/security-operator/internal/client"
	"go.platform-mesh.io/subroutines"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlruntimeclient "sigs.k8s.io/controller-runtime/pkg/client"

	kcpcorev1alpha1 "github.com/kcp-dev/sdk/apis/core/v1alpha1"
)

// AuthorizationIntent replaces tuple-writing initializers in the opt-in PoC.
// It only creates intent; the independently deployed controller owns projection.
type AuthorizationIntent struct{ Clients iclient.KCPClientGetter }

func (s *AuthorizationIntent) GetName() string { return "AuthorizationIntent" }
func (s *AuthorizationIntent) Initialize(ctx context.Context, obj ctrlruntimeclient.Object) (subroutines.Result, error) {
	return s.Process(ctx, obj)
}
func (s *AuthorizationIntent) Process(ctx context.Context, obj ctrlruntimeclient.Object) (subroutines.Result, error) {
	lc := obj.(*kcpcorev1alpha1.LogicalCluster)
	if lc.Spec.Owner == nil {
		return subroutines.OK(), fmt.Errorf("logical cluster has no account owner")
	}
	c, err := s.Clients.NewClientForLogicalCluster(ctx, lc.Spec.Owner.Cluster)
	if err != nil {
		return subroutines.OK(), err
	}
	var account pmcorev1alpha1.Account
	if err := c.Get(ctx, ctrlruntimeclient.ObjectKey{Name: lc.Spec.Owner.Name}, &account); err != nil {
		return subroutines.OK(), err
	}
	if account.Spec.Creator == nil || *account.Spec.Creator == "" {
		return subroutines.OK(), fmt.Errorf("account creator is required")
	}
	name := "bootstrap-" + string(account.UID)
	var grant pmcorev1alpha1.AuthorizationGrant
	if err := c.Get(ctx, ctrlruntimeclient.ObjectKey{Name: name}, &grant); apierrors.IsNotFound(err) {
		if account.Annotations["authz.platform-mesh.io/bootstrap-created"] == "true" {
			return subroutines.OK(), nil
		}
		grant = pmcorev1alpha1.AuthorizationGrant{ObjectMeta: metav1.ObjectMeta{Name: name, Finalizers: []string{pmcorev1alpha1.AuthorizationGrantFinalizer}, Labels: map[string]string{"authz.platform-mesh.io/bootstrap": "true"}}, Spec: pmcorev1alpha1.AuthorizationGrantSpec{AccountRef: pmcorev1alpha1.GrantAccountReference{Name: account.Name, UID: string(account.UID)}, Subject: pmcorev1alpha1.GrantSubject{Kind: "User", Name: *account.Spec.Creator}, RoleRef: "account-editor", Propagation: "Local", State: "Active"}}
		if err := c.Create(ctx, &grant); err != nil {
			return subroutines.OK(), err
		}
	} else if err != nil {
		return subroutines.OK(), err
	}
	if !meta.IsStatusConditionTrue(grant.Status.Conditions, "Reconciled") || grant.Status.ObservedGeneration != grant.Generation {
		return subroutines.StopWithRequeue(time.Second, "waiting for authorization intent"), nil
	}
	if account.Annotations["authz.platform-mesh.io/bootstrap-created"] != "true" {
		before := account.DeepCopy()
		if account.Annotations == nil {
			account.Annotations = map[string]string{}
		}
		account.Annotations["authz.platform-mesh.io/bootstrap-created"] = "true"
		if err := c.Patch(ctx, &account, ctrlruntimeclient.MergeFrom(before)); err != nil {
			return subroutines.OK(), err
		}
	}
	return subroutines.OK(), nil
}
func (s *AuthorizationIntent) Terminate(ctx context.Context, obj ctrlruntimeclient.Object) (subroutines.Result, error) {
	lc := obj.(*kcpcorev1alpha1.LogicalCluster)
	if lc.Spec.Owner == nil {
		return subroutines.OK(), fmt.Errorf("logical cluster has no account owner")
	}
	c, err := s.Clients.NewClientForLogicalCluster(ctx, lc.Spec.Owner.Cluster)
	if err != nil {
		return subroutines.OK(), err
	}
	var grants pmcorev1alpha1.AuthorizationGrantList
	if err := c.List(ctx, &grants); err != nil {
		return subroutines.OK(), err
	}
	for i := range grants.Items {
		g := &grants.Items[i]
		if g.Spec.AccountRef.Name != lc.Spec.Owner.Name {
			continue
		}
		if g.Spec.State != "Revoked" {
			before := g.DeepCopy()
			g.Spec.State = "Revoked"
			if err := c.Patch(ctx, g, ctrlruntimeclient.MergeFrom(before)); err != nil {
				return subroutines.OK(), err
			}
			return subroutines.StopWithRequeue(time.Second, "revoking account grants"), nil
		}
		if g.Status.ObservedGeneration != g.Generation || !meta.IsStatusConditionTrue(g.Status.Conditions, "Reconciled") {
			return subroutines.StopWithRequeue(time.Second, "waiting for authorization cleanup"), nil
		}
	}
	return subroutines.OK(), nil
}
