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

package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// AuthorizationGrantFinalizer protects backend cleanup before grant deletion.
const AuthorizationGrantFinalizer = "core.platform-mesh.io/authorization-projection"

// GrantAccountReference identifies an Account in the grant's workspace.
type GrantAccountReference struct {
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// +kubebuilder:validation:MinLength=1
	UID string `json:"uid"`
}

// GrantSubject identifies an authenticated principal.
type GrantSubject struct {
	// +kubebuilder:validation:Enum=User
	Kind string `json:"kind"`
	// Name is the canonical authenticated username, never an invitation email.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

// AuthorizationGrantSpec is experimental authorization intent for account contents.
// +kubebuilder:validation:XValidation:rule="self.accountRef == oldSelf.accountRef",message="accountRef is immutable"
// +kubebuilder:validation:XValidation:rule="self.subject == oldSelf.subject",message="subject is immutable"
// +kubebuilder:validation:XValidation:rule="self.roleRef == oldSelf.roleRef",message="roleRef is immutable"
// +kubebuilder:validation:XValidation:rule="self.propagation == oldSelf.propagation",message="propagation is immutable"
type AuthorizationGrantSpec struct {
	AccountRef GrantAccountReference `json:"accountRef"`
	Subject    GrantSubject          `json:"subject"`
	// +kubebuilder:validation:Enum=account-reader;account-editor
	RoleRef string `json:"roleRef"`
	// +kubebuilder:validation:Enum=Local;Descendants
	Propagation string `json:"propagation"`
	// +kubebuilder:validation:Enum=Active;Revoked
	State string `json:"state"`
}

// AuthorizationGrantStatus records observed projection and resolved scope.
type AuthorizationGrantStatus struct {
	// Workspace is the resolved logical cluster identity, used for safe cleanup.
	Workspace          string `json:"workspace,omitempty"`
	ObservedGeneration int64  `json:"observedGeneration,omitempty"`
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// AuthorizationGrant is an experimental, backend-neutral grant. Only trusted
// controllers and administrators may manage grants in the PoC.
// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:subresource:status
type AuthorizationGrant struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              AuthorizationGrantSpec   `json:"spec"`
	Status            AuthorizationGrantStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type AuthorizationGrantList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AuthorizationGrant `json:"items"`
}
