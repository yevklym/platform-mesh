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
	"fmt"
	"testing"

	fga "github.com/openfga/api/proto/openfga/v1"
	"google.golang.org/grpc"

	pmcorev1alpha1 "go.platform-mesh.io/apis/core/v1alpha1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type uncertainWrites struct {
	fga.OpenFGAServiceClient
	tuples           map[string]*fga.TupleKey
	loseNextResponse bool
}

func tupleID(user, relation, object string) string { return user + "|" + relation + "|" + object }
func (m *uncertainWrites) Read(_ context.Context, req *fga.ReadRequest, _ ...grpc.CallOption) (*fga.ReadResponse, error) {
	res := &fga.ReadResponse{}
	k := req.TupleKey
	if v, ok := m.tuples[tupleID(k.User, k.Relation, k.Object)]; ok {
		res.Tuples = []*fga.Tuple{{Key: v}}
	}
	return res, nil
}
func (m *uncertainWrites) Write(_ context.Context, req *fga.WriteRequest, _ ...grpc.CallOption) (*fga.WriteResponse, error) {
	for _, key := range req.GetWrites().GetTupleKeys() {
		id := tupleID(key.User, key.Relation, key.Object)
		if _, exists := m.tuples[id]; exists {
			return nil, fmt.Errorf("duplicate write")
		}
		m.tuples[id] = key
	}
	for _, key := range req.GetDeletes().GetTupleKeys() {
		delete(m.tuples, tupleID(key.User, key.Relation, key.Object))
	}
	if m.loseNextResponse {
		m.loseNextResponse = false
		return nil, fmt.Errorf("response lost after commit")
	}
	return &fga.WriteResponse{}, nil
}
func TestFGARetryAfterUnknownWriteOutcome(t *testing.T) {
	m := &uncertainWrites{tuples: map[string]*fga.TupleKey{}, loseNextResponse: true}
	b := FGA{Client: m}
	g := &pmcorev1alpha1.AuthorizationGrant{ObjectMeta: metav1.ObjectMeta{UID: "grant"}, Spec: pmcorev1alpha1.AuthorizationGrantSpec{Subject: pmcorev1alpha1.GrantSubject{Kind: "User", Name: "alice"}, RoleRef: "account-reader", Propagation: "Local", State: "Active"}}
	ctx := context.Background()
	if err := b.Apply(ctx, g, "target"); err == nil {
		t.Fatal("did not surface unknown write outcome")
	}
	if err := b.Apply(ctx, g, "target"); err != nil {
		t.Fatal(err)
	}
	if len(m.tuples) != 2 {
		t.Fatal("retry failed to converge")
	}
	g.Spec.State = "Revoked"
	m.loseNextResponse = true
	if err := b.Apply(ctx, g, "target"); err == nil {
		t.Fatal("did not surface unknown delete outcome")
	}
	if err := b.Apply(ctx, g, "target"); err != nil {
		t.Fatal(err)
	}
	if len(m.tuples) != 0 {
		t.Fatal("revocation left permissions behind")
	}
}
