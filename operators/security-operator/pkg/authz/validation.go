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
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	pmcorev1alpha1 "go.platform-mesh.io/apis/core/v1alpha1"

	authorizationv1 "k8s.io/api/authorization/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	ctrlruntimeclient "sigs.k8s.io/controller-runtime/pkg/client"

	kcptenancyv1alpha1 "github.com/kcp-dev/sdk/apis/tenancy/v1alpha1"
)

// ValidationCase makes expected results explicit; the runner never substitutes
// backend checks for actual API access or silently treats transport errors as deny.
type ValidationCase struct {
	Group           string `json:"group,omitempty"`
	Version         string `json:"version,omitempty"`
	Resource        string `json:"resource,omitempty"`
	Namespace       string `json:"namespace,omitempty"`
	Name            string `json:"name,omitempty"`
	Verb            string `json:"verb,omitempty"`
	ID              string `json:"id"`
	Parent          string `json:"parent"`
	Account         string `json:"account"`
	User            string `json:"user"`
	GrantName       string `json:"grantName,omitempty"`
	State           string `json:"state,omitempty"`
	Role            string `json:"role,omitempty"`
	Propagation     string `json:"propagation,omitempty"`
	ExpectedAllowed bool   `json:"expectedAllowed"`
	ExpectedReason  string `json:"expectedReason,omitempty"`
}

// ValidationResult records observed API and access-review behavior.
type ValidationResult struct {
	ReviewMode     string             `json:"reviewMode,omitempty"`
	ID             string             `json:"id"`
	Classification string             `json:"classification"`
	APIAllowed     bool               `json:"apiAllowed"`
	ReviewAllowed  bool               `json:"reviewAllowed"`
	Reason         string             `json:"reason,omitempty"`
	Seconds        float64            `json:"seconds"`
	Conditions     []metav1.Condition `json:"conditions,omitempty"`
}

// ValidationReport is the reproducible evidence bundle index.
type ValidationReport struct {
	Profile      string             `json:"profile"`
	Revision     string             `json:"revision"`
	Started      time.Time          `json:"started"`
	IdentityMode string             `json:"identityMode"`
	Results      []ValidationResult `json:"results"`
}

// ValidateCases performs grant mutations as administrator and measures reads of
// AccountInfo using a newly configured, ordinary impersonated client.
func ValidateCases(ctx context.Context, base *rest.Config, schemeClient ClientFor, cases []ValidationCase) ([]ValidationResult, error) {
	var results []ValidationResult
	for _, test := range cases {
		if test.Resource == "" {
			test.Group = "core.platform-mesh.io"
			test.Resource = "accountinfos"
			test.Name = "account"
		}
		if test.Version == "" {
			test.Version = "v1alpha1"
		}
		if test.Verb == "" {
			test.Verb = "get"
		}
		start := time.Now()
		result := ValidationResult{ID: test.ID, Classification: "defect"}
		err := func() error {
			if test.ID == "" || test.Parent == "" || test.Account == "" || test.User == "" {
				return fmt.Errorf("id, parent, account and user are required")
			}
			source, err := schemeClient(test.Parent)
			if err != nil {
				return err
			}
			var a pmcorev1alpha1.Account
			if err := source.Get(ctx, ctrlruntimeclient.ObjectKey{Name: test.Account}, &a); err != nil {
				return err
			}
			var ws kcptenancyv1alpha1.Workspace
			if err := source.Get(ctx, ctrlruntimeclient.ObjectKey{Name: test.Account}, &ws); err != nil {
				return err
			}
			target := string(ws.Spec.Cluster)
			if target == "" {
				return fmt.Errorf("account workspace is not scheduled")
			}
			var grant pmcorev1alpha1.AuthorizationGrant
			if test.GrantName != "" {
				err := source.Get(ctx, ctrlruntimeclient.ObjectKey{Name: test.GrantName}, &grant)
				if apierrors.IsNotFound(err) {
					grant = pmcorev1alpha1.AuthorizationGrant{ObjectMeta: metav1.ObjectMeta{Name: test.GrantName, Labels: map[string]string{"authz.platform-mesh.io/validation": "true"}}, Spec: pmcorev1alpha1.AuthorizationGrantSpec{AccountRef: pmcorev1alpha1.GrantAccountReference{Name: a.Name, UID: string(a.UID)}, Subject: pmcorev1alpha1.GrantSubject{Kind: "User", Name: test.User}, RoleRef: test.Role, Propagation: test.Propagation, State: test.State}}
					if err := source.Create(ctx, &grant); err != nil {
						return err
					}
				} else if err != nil {
					return err
				} else if test.State != "" {
					before := grant.DeepCopy()
					grant.Spec.State = test.State
					if err := source.Patch(ctx, &grant, ctrlruntimeclient.MergeFrom(before)); err != nil {
						return err
					}
				}
			}
			cfg := WorkspaceConfig(base, target)
			cfg.Impersonate = rest.ImpersonationConfig{UserName: test.User, Groups: []string{"system:authenticated"}}
			// Reuse the scheme from the administrator client, with a distinct identity.
			measured, err := ctrlruntimeclient.New(cfg, ctrlruntimeclient.Options{Scheme: source.Scheme()})
			if err != nil {
				return err
			}
			kube, err := kubernetes.NewForConfig(cfg)
			if err != nil {
				return err
			}
			attemptCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			for {
				ready := true
				if test.GrantName != "" {
					if err := source.Get(attemptCtx, ctrlruntimeclient.ObjectKey{Name: test.GrantName}, &grant); err != nil {
						return err
					}
					result.Conditions = grant.Status.Conditions
					ready = grant.Status.ObservedGeneration == grant.Generation && meta.IsStatusConditionTrue(grant.Status.Conditions, "Reconciled")
					if test.ExpectedReason != "" {
						condition := meta.FindStatusCondition(grant.Status.Conditions, "Reconciled")
						ready = condition != nil && condition.ObservedGeneration == grant.Generation && condition.Reason == test.ExpectedReason
						if test.ExpectedReason == "Pending" {
							ready = grant.Status.ObservedGeneration < grant.Generation
						}
					}
				}
				var getErr error
				object := &unstructured.Unstructured{}
				kind := "AccountInfo"
				if test.Resource == "httpbins" {
					kind = "HttpBin"
				} else if test.Resource == "authorizationgrants" {
					kind = "AuthorizationGrant"
				}
				object.SetGroupVersionKind(schema.GroupVersionKind{Group: test.Group, Version: test.Version, Kind: kind})
				object.SetName(test.Name)
				object.SetNamespace(test.Namespace)
				switch test.Verb {
				case "get":
					getErr = measured.Get(attemptCtx, ctrlruntimeclient.ObjectKey{Name: test.Name, Namespace: test.Namespace}, object)
				case "create":
					if test.Resource != "httpbins" {
						return fmt.Errorf("create probes support only HTTPBin")
					}
					getErr = measured.Create(attemptCtx, object, ctrlruntimeclient.DryRunAll)
				default:
					return fmt.Errorf("unsupported probe verb %q", test.Verb)
				}
				if getErr != nil && !apierrors.IsForbidden(getErr) {
					return fmt.Errorf("API probe failed before an authorization decision: %w", getErr)
				}
				result.APIAllowed = getErr == nil
				review, err := kube.AuthorizationV1().SelfSubjectAccessReviews().Create(attemptCtx, &authorizationv1.SelfSubjectAccessReview{Spec: authorizationv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authorizationv1.ResourceAttributes{Group: test.Group, Version: test.Version, Resource: test.Resource, Namespace: test.Namespace, Name: test.Name, Verb: test.Verb}}}, metav1.CreateOptions{})
				result.ReviewMode = "SelfSubjectAccessReview"
				if apierrors.IsForbidden(err) {
					// A revoked identity may lack permission even to create an
					// SSAR. Submit an exact-subject SAR through the same target
					// kcp chain, retaining this distinction in the evidence.
					admin, adminErr := kubernetes.NewForConfig(WorkspaceConfig(base, target))
					if adminErr != nil {
						return adminErr
					}
					sar, sarErr := admin.AuthorizationV1().SubjectAccessReviews().Create(attemptCtx, &authorizationv1.SubjectAccessReview{Spec: authorizationv1.SubjectAccessReviewSpec{User: test.User, Groups: []string{"system:authenticated"}, ResourceAttributes: &authorizationv1.ResourceAttributes{Group: test.Group, Version: test.Version, Resource: test.Resource, Namespace: test.Namespace, Name: test.Name, Verb: test.Verb}}}, metav1.CreateOptions{})
					if sarErr != nil {
						return fmt.Errorf("subject access review: %w", sarErr)
					}
					review = &authorizationv1.SelfSubjectAccessReview{Status: sar.Status}
					err = nil
					result.ReviewMode = "SubjectAccessReview (administrator submitted)"
				}
				if err != nil {
					return fmt.Errorf("self access review: %w", err)
				}
				if review.Status.EvaluationError != "" {
					return fmt.Errorf("self access review evaluation failed: %s", review.Status.EvaluationError)
				}
				result.ReviewAllowed = review.Status.Allowed
				if ready && result.APIAllowed == test.ExpectedAllowed && result.ReviewAllowed == test.ExpectedAllowed {
					result.Classification = "preserved"
					if test.ExpectedReason == "UnsupportedCapability" {
						result.Classification = "unsupported"
					}
					return nil
				}
				select {
				case <-attemptCtx.Done():
					return fmt.Errorf("did not converge within 30s")
				case <-time.After(250 * time.Millisecond):
				}
			}
		}()
		result.Seconds = time.Since(start).Seconds()
		if err != nil {
			result.Reason = err.Error()
		}
		results = append(results, result)
	}
	return results, nil
}

// WorkspaceConfig copies credentials and selects a target kcp workspace.
func WorkspaceConfig(base *rest.Config, workspace string) *rest.Config {
	cfg := rest.CopyConfig(base)
	cfg.Host = strings.Split(cfg.Host, "/clusters/")[0] + "/clusters/" + workspace
	return cfg
}

// WriteReport writes JSON, Markdown and JUnit without hiding scenario failures.
func WriteReport(directory string, report ValidationReport) error {
	if err := os.MkdirAll(directory, 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(directory, "results.json"), append(data, '\n'), 0644); err != nil {
		return err
	}
	var markdown strings.Builder
	fmt.Fprintf(&markdown, "# Authorization PoC results: %s\n\nRevision: %s\n\nIdentity: %s\n\n| Scenario | Result | API allow | Review allow | Seconds | Detail |\n|---|---|---|---|---|---|\n", report.Profile, report.Revision, report.IdentityMode)
	type junitCase struct {
		Name    string  `xml:"name,attr"`
		Time    string  `xml:"time,attr"`
		Failure *string `xml:"failure,omitempty"`
	}
	suite := struct {
		XMLName xml.Name    `xml:"testsuite"`
		Name    string      `xml:"name,attr"`
		Cases   []junitCase `xml:"testcase"`
	}{Name: report.Profile}
	for _, r := range report.Results {
		detail := strings.ReplaceAll(strings.ReplaceAll(r.Reason, "|", "/"), "\n", " ")
		fmt.Fprintf(&markdown, "| %s | %s | %t | %t | %.3f | %s |\n", r.ID, r.Classification, r.APIAllowed, r.ReviewAllowed, r.Seconds, detail)
		item := junitCase{Name: r.ID, Time: fmt.Sprintf("%.3f", r.Seconds)}
		if r.Classification == "defect" {
			reason := r.Reason
			item.Failure = &reason
		}
		suite.Cases = append(suite.Cases, item)
	}
	if err := os.WriteFile(filepath.Join(directory, "results.md"), []byte(markdown.String()), 0644); err != nil {
		return err
	}
	data, err = xml.MarshalIndent(suite, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(directory, "junit.xml"), data, 0644)
}
