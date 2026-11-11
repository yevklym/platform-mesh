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
	"fmt"
	"sync"
	"time"

	fga "github.com/openfga/api/proto/openfga/v1"
	language "github.com/openfga/language/pkg/go/transformer"

	pmcorev1alpha1 "go.platform-mesh.io/apis/core/v1alpha1"
)

// Model defines local roles and explicit descendant propagation for the PoC.
const Model = `model
 schema 1.1
type user
type grant
 relations
  define assignee: [user]
type binding
 relations
  define consumer: [workspace]
type export
 relations
  define bind: [binding#consumer]
type workspace
 relations
  define parent: [workspace]
  define local_reader: [grant#assignee]
  define local_editor: [grant#assignee]
  define descendant_reader: [grant#assignee] or descendant_reader from parent
  define descendant_editor: [grant#assignee] or descendant_editor from parent
  define editor: local_editor or descendant_editor
  define reader: local_reader or descendant_reader or editor
`

// FGA owns a dedicated experimental store; it never changes legacy stores.
type FGA struct {
	Client           fga.OpenFGAServiceClient
	StoreID, ModelID string
	mu               sync.Mutex
}

// NewFGA initializes the dedicated PoC store and pins an immutable model.
func NewFGA(ctx context.Context, c fga.OpenFGAServiceClient, storeName string) (*FGA, error) {
	b := &FGA{Client: c}
	token := ""
	for {
		stores, err := c.ListStores(ctx, &fga.ListStoresRequest{ContinuationToken: token})
		if err != nil {
			return nil, err
		}
		for _, s := range stores.Stores {
			if s.Name == storeName {
				if b.StoreID != "" {
					return nil, fmt.Errorf("ambiguous PoC store name")
				}
				b.StoreID = s.Id
			}
		}
		token = stores.ContinuationToken
		if token == "" {
			break
		}
	}
	if b.StoreID == "" {
		s, err := c.CreateStore(ctx, &fga.CreateStoreRequest{Name: storeName})
		if err != nil {
			return nil, err
		}
		b.StoreID = s.Id
	}
	model, err := language.TransformDSLToProto(Model)
	if err != nil {
		return nil, err
	}
	// A model is immutable; this command pins all writes/checks to its model ID.
	res, err := c.WriteAuthorizationModel(ctx, &fga.WriteAuthorizationModelRequest{StoreId: b.StoreID, SchemaVersion: model.SchemaVersion, TypeDefinitions: model.TypeDefinitions})
	if err != nil {
		return nil, err
	}
	b.ModelID = res.AuthorizationModelId
	return b, nil
}

// LoadFGA opens an already initialized PoC store without changing its model.
func LoadFGA(ctx context.Context, c fga.OpenFGAServiceClient, name string) (*FGA, error) {
	b := &FGA{Client: c}
	token := ""
	for {
		stores, err := c.ListStores(ctx, &fga.ListStoresRequest{ContinuationToken: token})
		if err != nil {
			return nil, err
		}
		for _, store := range stores.Stores {
			if store.Name == name {
				if b.StoreID != "" {
					return nil, fmt.Errorf("ambiguous PoC store name")
				}
				b.StoreID = store.Id
			}
		}
		token = stores.ContinuationToken
		if token == "" {
			break
		}
	}
	if b.StoreID == "" {
		return nil, fmt.Errorf("waiting for projection controller to initialize PoC store")
	}
	models, err := c.ReadAuthorizationModels(ctx, &fga.ReadAuthorizationModelsRequest{StoreId: b.StoreID})
	if err != nil {
		return nil, err
	}
	if len(models.AuthorizationModels) == 0 {
		return nil, fmt.Errorf("PoC store has no model")
	}
	b.ModelID = models.AuthorizationModels[0].Id
	return b, nil
}

func userKey(name string) string { return fmt.Sprintf("user:%x", sha256.Sum256([]byte(name))) }
func workspaceKey(name string) string {
	return fmt.Sprintf("workspace:%x", sha256.Sum256([]byte(name)))
}

// syncTuple performs a desired-state operation, so retries after unknown write
// outcomes remain safe. Writes are serialized inside the PoC process.
func (b *FGA) syncTuple(ctx context.Context, key *fga.TupleKey, active bool) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	read, err := b.Client.Read(ctx, &fga.ReadRequest{StoreId: b.StoreID, TupleKey: &fga.ReadRequestTupleKey{User: key.User, Relation: key.Relation, Object: key.Object}, Consistency: fga.ConsistencyPreference_HIGHER_CONSISTENCY})
	if err != nil {
		return err
	}
	exists := len(read.Tuples) > 0
	if exists == active {
		return nil
	}
	req := &fga.WriteRequest{StoreId: b.StoreID, AuthorizationModelId: b.ModelID}
	if active {
		req.Writes = &fga.WriteRequestWrites{TupleKeys: []*fga.TupleKey{key}}
	} else {
		req.Deletes = &fga.WriteRequestDeletes{TupleKeys: []*fga.TupleKeyWithoutCondition{{User: key.User, Relation: key.Relation, Object: key.Object}}}
	}
	_, err = b.Client.Write(ctx, req)
	return err
}

// Apply reconciles a grant without affecting other grants for the same subject.
func (b *FGA) Apply(ctx context.Context, g *pmcorev1alpha1.AuthorizationGrant, workspace string) error {
	if err := Validate(g); err != nil {
		return err
	}
	relation := "local_reader"
	if g.Spec.RoleRef == "account-editor" {
		relation = "local_editor"
	}
	if g.Spec.Propagation == "Descendants" {
		relation = "descendant_reader"
		if g.Spec.RoleRef == "account-editor" {
			relation = "descendant_editor"
		}
	}
	grant := "grant:" + string(g.UID)
	active := g.Spec.State == "Active" && g.DeletionTimestamp.IsZero()
	assignment := &fga.TupleKey{User: userKey(g.Spec.Subject.Name), Relation: "assignee", Object: grant}
	permission := &fga.TupleKey{User: grant + "#assignee", Relation: relation, Object: workspaceKey(workspace)}
	// Remove the effective permission before removing its assignment on revocation.
	if !active {
		if err := b.syncTuple(ctx, permission, false); err != nil {
			return err
		}
		return b.syncTuple(ctx, assignment, false)
	}
	if err := b.syncTuple(ctx, assignment, true); err != nil {
		return err
	}
	return b.syncTuple(ctx, permission, true)
}

// Parent records account topology for explicit descendant propagation.
func (b *FGA) Parent(ctx context.Context, child, parent string) error {
	return b.syncTuple(ctx, &fga.TupleKey{Object: workspaceKey(child), Relation: "parent", User: workspaceKey(parent)}, true)
}

// Check evaluates a portable role in the target logical workspace.
func (b *FGA) Check(ctx context.Context, user, workspace, relation string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	res, err := b.Client.Check(ctx, &fga.CheckRequest{StoreId: b.StoreID, AuthorizationModelId: b.ModelID, TupleKey: &fga.CheckRequestTupleKey{User: userKey(user), Object: workspaceKey(workspace), Relation: relation}, Consistency: fga.ConsistencyPreference_HIGHER_CONSISTENCY})
	if err != nil {
		return false, err
	}
	return res.Allowed, nil
}
