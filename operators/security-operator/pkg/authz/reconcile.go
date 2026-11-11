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
	"slices"
	"strings"

	pmcorev1alpha1 "go.platform-mesh.io/apis/core/v1alpha1"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlruntimeclient "sigs.k8s.io/controller-runtime/pkg/client"

	kcptenancyv1alpha1 "github.com/kcp-dev/sdk/apis/tenancy/v1alpha1"
)

// ClientFor returns an administrator client scoped to one logical workspace.
type ClientFor func(string) (ctrlruntimeclient.Client, error)

// Reconciler uses direct workspace clients. The deliberately small PoC polls
// explicitly configured parent workspaces and does not need an FGA APIExport.
type Reconciler struct {
	ClientFor ClientFor
	Backend   string
	FGA       *FGA
}

// Once reconciles grants and binding eligibility in a parent workspace.
func (r *Reconciler) Once(ctx context.Context, parent string) error {
	c, err := r.ClientFor(parent)
	if err != nil {
		return err
	}
	var grants pmcorev1alpha1.AuthorizationGrantList
	if err := c.List(ctx, &grants); err != nil {
		return err
	}
	var errs []error
	for i := range grants.Items {
		if err := r.Reconcile(ctx, c, &grants.Items[i]); err != nil && !errors.Is(err, ErrUnsupportedCapability) {
			errs = append(errs, fmt.Errorf("grant %s: %w", grants.Items[i].Name, err))
		}
	}
	var policies pmcorev1alpha1.APIExportPolicyList
	if err := c.List(ctx, &policies); err != nil {
		// Policy intent is served by the system export, which is not bound in
		// every account workspace. Its absence does not block local grants.
		if !meta.IsNoMatchError(err) {
			errs = append(errs, err)
		}
	} else {
		for i := range policies.Items {
			if err := r.Policy(ctx, c, &policies.Items[i]); err != nil {
				policy := &policies.Items[i]
				before := policy.DeepCopy()
				reason := "ProjectionFailed"
				if strings.HasPrefix(err.Error(), "UnsupportedCapability") {
					reason = "UnsupportedCapability"
				}
				meta.SetStatusCondition(&policy.Status.Conditions, metav1.Condition{Type: "Reconciled", Status: metav1.ConditionFalse, Reason: reason, Message: err.Error(), ObservedGeneration: policy.Generation})
				if statusErr := c.Status().Patch(ctx, policy, ctrlruntimeclient.MergeFrom(before)); statusErr != nil {
					errs = append(errs, statusErr)
				}
				if !errors.Is(err, ErrUnsupportedCapability) {
					errs = append(errs, fmt.Errorf("policy %s: %w", policies.Items[i].Name, err))
				}
			}
		}
	}
	return errors.Join(errs...)
}

// Reconcile resolves immutable account scope and projects the desired grant.
func (r *Reconciler) Reconcile(ctx context.Context, c ctrlruntimeclient.Client, g *pmcorev1alpha1.AuthorizationGrant) error {
	if err := Validate(g); err != nil {
		return r.status(ctx, c, g, "InvalidIntent", err)
	}
	// Install the finalizer before any backend write, including during replay.
	if g.DeletionTimestamp.IsZero() && !slices.Contains(g.Finalizers, Finalizer) {
		before := g.DeepCopy()
		g.Finalizers = append(g.Finalizers, Finalizer)
		return c.Patch(ctx, g, ctrlruntimeclient.MergeFrom(before))
	}
	var account pmcorev1alpha1.Account
	err := c.Get(ctx, ctrlruntimeclient.ObjectKey{Name: g.Spec.AccountRef.Name}, &account)
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	missing := apierrors.IsNotFound(err)
	stale := !missing && string(account.UID) != g.Spec.AccountRef.UID
	target := g.Status.Workspace
	if !stale && !missing {
		var ws kcptenancyv1alpha1.Workspace
		if err := c.Get(ctx, ctrlruntimeclient.ObjectKey{Name: g.Spec.AccountRef.Name}, &ws); err != nil {
			return r.status(ctx, c, g, "WorkspacePending", err)
		}
		target = string(ws.Spec.Cluster)
	}
	if target == "" {
		if !g.DeletionTimestamp.IsZero() && g.Status.Workspace == "" {
			before := g.DeepCopy()
			g.Finalizers = slices.DeleteFunc(g.Finalizers, func(s string) bool { return s == Finalizer })
			return c.Patch(ctx, g, ctrlruntimeclient.MergeFrom(before))
		}
		if stale {
			return r.status(ctx, c, g, "AccountUIDMismatch", fmt.Errorf("account has been replaced"))
		}
		return r.status(ctx, c, g, "WorkspacePending", fmt.Errorf("workspace is not scheduled"))
	}
	// Persist resolved scope before backend writes so cleanup survives deletion.
	if g.Status.Workspace == "" {
		before := g.DeepCopy()
		g.Status.Workspace = target
		return c.Status().Patch(ctx, g, ctrlruntimeclient.MergeFrom(before))
	}
	if !missing && !stale && len(g.OwnerReferences) == 0 {
		before := g.DeepCopy()
		g.OwnerReferences = []metav1.OwnerReference{{APIVersion: pmcorev1alpha1.SchemeGroupVersion.String(), Kind: "Account", Name: account.Name, UID: account.UID}}
		return c.Patch(ctx, g, ctrlruntimeclient.MergeFrom(before))
	}
	projected := g.DeepCopy()
	if stale || missing || !account.DeletionTimestamp.IsZero() {
		projected.Spec.State = "Revoked"
	}
	if r.Backend == "rbac" {
		targetClient, clientErr := r.ClientFor(target)
		if clientErr != nil {
			return r.status(ctx, c, g, "ProjectionFailed", clientErr)
		}
		err = (&RBAC{Client: targetClient}).Apply(ctx, projected)
	} else if r.Backend == "openfga" && r.FGA != nil {
		var info pmcorev1alpha1.AccountInfo
		if infoErr := c.Get(ctx, ctrlruntimeclient.ObjectKey{Name: "account"}, &info); infoErr == nil {
			if err = r.FGA.Parent(ctx, target, info.Spec.Account.GeneratedClusterId); err != nil {
				return r.status(ctx, c, g, "ProjectionFailed", err)
			}
		} else if !apierrors.IsNotFound(infoErr) {
			return infoErr
		}
		err = r.FGA.Apply(ctx, projected, target)
	} else {
		err = fmt.Errorf("invalid backend")
	}
	if err != nil {
		reason := "ProjectionFailed"
		if strings.HasPrefix(err.Error(), "UnsupportedCapability") {
			reason = "UnsupportedCapability"
		}
		return r.status(ctx, c, g, reason, err)
	}
	if !g.DeletionTimestamp.IsZero() {
		if g.Labels["authz.platform-mesh.io/bootstrap"] == "true" && !missing && account.DeletionTimestamp.IsZero() {
			return r.status(ctx, c, g, "BootstrapRetained", nil)
		}
		before := g.DeepCopy()
		g.Finalizers = slices.DeleteFunc(g.Finalizers, func(s string) bool { return s == Finalizer })
		return c.Patch(ctx, g, ctrlruntimeclient.MergeFrom(before))
	}
	if stale {
		return r.status(ctx, c, g, "AccountUIDMismatch", fmt.Errorf("stale scope cleaned; account has been replaced"))
	}
	return r.status(ctx, c, g, "Reconciled", nil)
}
func (r *Reconciler) status(ctx context.Context, c ctrlruntimeclient.Client, g *pmcorev1alpha1.AuthorizationGrant, reason string, cause error) error {
	before := g.DeepCopy()
	state := metav1.ConditionTrue
	message := "backend matches desired state"
	if cause != nil {
		state = metav1.ConditionFalse
		message = cause.Error()
	}
	g.Status.ObservedGeneration = g.Generation
	meta.SetStatusCondition(&g.Status.Conditions, metav1.Condition{Type: "Reconciled", Status: state, Reason: reason, Message: message, ObservedGeneration: g.Generation})
	if err := c.Status().Patch(ctx, g, ctrlruntimeclient.MergeFrom(before)); err != nil {
		return err
	}
	return cause
}
