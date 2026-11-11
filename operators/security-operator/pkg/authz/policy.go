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
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	fga "github.com/openfga/api/proto/openfga/v1"

	pmcorev1alpha1 "go.platform-mesh.io/apis/core/v1alpha1"

	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlruntimeclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	kcpcorev1alpha1 "github.com/kcp-dev/sdk/apis/core/v1alpha1"
)

// Policy reconciles the exact-path portable subset of APIExportPolicy. A
// provider's binding eligibility is independent of permissions on its resources.
func (r *Reconciler) Policy(ctx context.Context, c ctrlruntimeclient.Client, p *pmcorev1alpha1.APIExportPolicy) error {
	const referenceKey = "authz.platform-mesh.io/projected-export-ref"
	reference, err := json.Marshal(p.Spec.APIExportRef)
	if err != nil {
		return err
	}
	oldReference := p.Annotations[referenceKey]
	if oldReference == "" {
		before := p.DeepCopy()
		if p.Annotations == nil {
			p.Annotations = map[string]string{}
		}
		p.Annotations[referenceKey] = string(reference)
		return c.Patch(ctx, p, ctrlruntimeclient.MergeFrom(before))
	}
	if oldReference != string(reference) {
		previous := p.DeepCopy()
		if err := json.Unmarshal([]byte(oldReference), &previous.Spec.APIExportRef); err != nil {
			return err
		}
		for _, expr := range p.Status.ManagedAllowExpressions {
			if err := r.binding(ctx, previous, expr, false); err != nil {
				return err
			}
		}
		before := p.DeepCopy()
		p.Status.ManagedAllowExpressions = nil
		if err := c.Status().Patch(ctx, p, ctrlruntimeclient.MergeFrom(before)); err != nil {
			return err
		}
		before = p.DeepCopy()
		p.Annotations[referenceKey] = string(reference)
		return c.Patch(ctx, p, ctrlruntimeclient.MergeFrom(before))
	}

	for _, expr := range p.Spec.AllowPathExpressions {
		if !strings.HasPrefix(expr, ":root:orgs:") || strings.ContainsAny(expr, "*?,") {
			return fmt.Errorf("%w: only exact root:orgs account paths are portable", ErrUnsupportedCapability)
		}
	}
	for _, expr := range p.Status.ManagedAllowExpressions {
		if !slices.Contains(p.Spec.AllowPathExpressions, expr) || !p.DeletionTimestamp.IsZero() {
			if err := r.binding(ctx, p, expr, false); err != nil {
				return err
			}
		}
	}
	if p.DeletionTimestamp.IsZero() {
		if !slices.Contains(p.Finalizers, Finalizer) {
			before := p.DeepCopy()
			p.Finalizers = append(p.Finalizers, Finalizer)
			return c.Patch(ctx, p, ctrlruntimeclient.MergeFrom(before))
		}
		for _, expr := range p.Spec.AllowPathExpressions {
			// Reserve cleanup ownership before writing. A later consumer can be
			// pending while earlier writes have already succeeded.
			if !slices.Contains(p.Status.ManagedAllowExpressions, expr) {
				before := p.DeepCopy()
				p.Status.ManagedAllowExpressions = append(p.Status.ManagedAllowExpressions, expr)
				return c.Status().Patch(ctx, p, ctrlruntimeclient.MergeFrom(before))
			}
			if err := r.binding(ctx, p, expr, true); err != nil {
				return err
			}
		}
		before := p.DeepCopy()
		p.Status.ManagedAllowExpressions = append([]string(nil), p.Spec.AllowPathExpressions...)
		meta.SetStatusCondition(&p.Status.Conditions, metav1.Condition{Type: "Reconciled", Status: metav1.ConditionTrue, Reason: "Reconciled", Message: "binding eligibility projected", ObservedGeneration: p.Generation})
		return c.Status().Patch(ctx, p, ctrlruntimeclient.MergeFrom(before))
	}
	before := p.DeepCopy()
	p.Finalizers = slices.DeleteFunc(p.Finalizers, func(s string) bool { return s == Finalizer })
	return c.Patch(ctx, p, ctrlruntimeclient.MergeFrom(before))
}
func (r *Reconciler) binding(ctx context.Context, p *pmcorev1alpha1.APIExportPolicy, path string, active bool) error {
	consumer, err := r.ClientFor(strings.TrimPrefix(path, ":"))
	if err != nil {
		return err
	}
	var lc kcpcorev1alpha1.LogicalCluster
	if err := consumer.Get(ctx, ctrlruntimeclient.ObjectKey{Name: "cluster"}, &lc); err != nil {
		if !active && apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}
	id := lc.Annotations["kcp.io/cluster"]
	if id == "" {
		return fmt.Errorf("consumer is not scheduled")
	}
	provider, err := r.ClientFor(p.Spec.APIExportRef.ClusterPath)
	if err != nil {
		return err
	}
	key := fmt.Sprintf("authz-poc-bind-%x", sha256.Sum256([]byte(string(p.UID)+"/"+id)))
	if r.Backend == "rbac" {
		role := &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: key}}
		binding := &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: key}}
		if !active {
			for _, obj := range []ctrlruntimeclient.Object{binding, role} {
				if err := provider.Delete(ctx, obj); err != nil && !apierrors.IsNotFound(err) {
					return err
				}
			}
			return nil
		}
		if _, err := controllerutil.CreateOrUpdate(ctx, provider, role, func() error {
			role.Rules = []rbacv1.PolicyRule{{APIGroups: []string{"apis.kcp.io"}, Resources: []string{"apiexports"}, ResourceNames: []string{p.Spec.APIExportRef.Name}, Verbs: []string{"bind"}}}
			return nil
		}); err != nil {
			return err
		}
		_, err := controllerutil.CreateOrUpdate(ctx, provider, binding, func() error {
			binding.RoleRef = rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: key}
			binding.Subjects = []rbacv1.Subject{{Kind: "Group", APIGroup: rbacv1.GroupName, Name: "system:cluster:" + id}}
			return nil
		})
		return err
	}
	if r.FGA == nil {
		return fmt.Errorf("missing FGA adapter")
	}
	if err := provider.Get(ctx, ctrlruntimeclient.ObjectKey{Name: "cluster"}, &lc); err != nil {
		return err
	}
	export := exportKey(lc.Annotations["kcp.io/cluster"], p.Spec.APIExportRef.Name)
	assignment := &fga.TupleKey{Object: "binding:" + key, Relation: "consumer", User: workspaceKey(id)}
	permission := &fga.TupleKey{Object: export, Relation: "bind", User: "binding:" + key + "#consumer"}
	if !active {
		if err := r.FGA.syncTuple(ctx, permission, false); err != nil {
			return err
		}
		return r.FGA.syncTuple(ctx, assignment, false)
	}
	if err := r.FGA.syncTuple(ctx, assignment, true); err != nil {
		return err
	}
	return r.FGA.syncTuple(ctx, permission, true)
}
func exportKey(cluster, name string) string {
	return fmt.Sprintf("export:%x", sha256.Sum256([]byte(cluster+"/"+name)))
}
