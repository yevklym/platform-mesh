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
	"errors"
	"fmt"

	pmcorev1alpha1 "go.platform-mesh.io/apis/core/v1alpha1"

	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlruntimeclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// Finalizer protects the lifetime of projected permissions.
const Finalizer = pmcorev1alpha1.AuthorizationGrantFinalizer

// ErrUnsupportedCapability marks terminal intent rejection rather than a failed backend operation.
var ErrUnsupportedCapability = errors.New("UnsupportedCapability")

// Rules is the entire portable PoC role catalog. Account writes and authorization
// management are intentionally absent: only trusted administrators provision.
func Rules(role string) ([]rbacv1.PolicyRule, error) {
	if role != "account-reader" && role != "account-editor" {
		return nil, fmt.Errorf("unsupported role %q", role)
	}
	rules := []rbacv1.PolicyRule{
		{APIGroups: []string{"authorization.k8s.io"}, Resources: []string{"selfsubjectaccessreviews"}, Verbs: []string{"create"}},
		{NonResourceURLs: []string{"/"}, Verbs: []string{"access"}},
		{APIGroups: []string{"core.platform-mesh.io"}, Resources: []string{"accounts", "accountinfos"}, Verbs: []string{"get", "list", "watch"}},
		{APIGroups: []string{"orchestrate.platform-mesh.io"}, Resources: []string{"httpbins"}, Verbs: []string{"get", "list", "watch"}},
	}
	if role == "account-editor" {
		rules[3].Verbs = append(rules[3].Verbs, "create", "update", "patch", "delete")
	}
	return rules, nil
}

// Validate rejects unsupported or unpersisted grant forms before projection.
func Validate(g *pmcorev1alpha1.AuthorizationGrant) error {
	if g.UID == "" {
		return fmt.Errorf("grant must be persisted before projection")
	}
	if g.Spec.Subject.Kind != "User" || g.Spec.Subject.Name == "" {
		return fmt.Errorf("only a non-empty canonical User is supported")
	}
	if g.Spec.State != "Active" && g.Spec.State != "Revoked" {
		return fmt.Errorf("unsupported state %q", g.Spec.State)
	}
	if g.Spec.Propagation != "Local" && g.Spec.Propagation != "Descendants" {
		return fmt.Errorf("unsupported propagation %q", g.Spec.Propagation)
	}
	_, err := Rules(g.Spec.RoleRef)
	return err
}

// RBAC writes one binding and role per grant UID in the target workspace.
// This preserves overlapping grants without deleting another owner's permission.
type RBAC struct{ Client ctrlruntimeclient.Client }

// Apply creates or revokes the independently owned native grant projection.
func (b *RBAC) Apply(ctx context.Context, g *pmcorev1alpha1.AuthorizationGrant) error {
	if err := Validate(g); err != nil {
		return err
	}

	name := "authz-poc-" + string(g.UID)
	binding := &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: name}}
	role := &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: name}}
	if g.Spec.State == "Revoked" || !g.DeletionTimestamp.IsZero() {
		for _, obj := range []ctrlruntimeclient.Object{binding, role} {
			if err := b.Client.Delete(ctx, obj); err != nil && !apierrors.IsNotFound(err) {
				return err
			}
		}
		return nil
	}
	if g.Spec.Propagation != "Local" {
		return fmt.Errorf("%w: Descendants", ErrUnsupportedCapability)
	}
	rules, _ := Rules(g.Spec.RoleRef)
	if _, err := controllerutil.CreateOrUpdate(ctx, b.Client, role, func() error { role.Rules = rules; return nil }); err != nil {
		return err
	}
	_, err := controllerutil.CreateOrUpdate(ctx, b.Client, binding, func() error {
		binding.Subjects = []rbacv1.Subject{{Kind: "User", APIGroup: rbacv1.GroupName, Name: g.Spec.Subject.Name}}
		binding.RoleRef = rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: name}
		return nil
	})
	return err
}
