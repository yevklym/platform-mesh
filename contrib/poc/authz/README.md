# Authorization modularization PoC

This experiment makes account access intent explicit and projects it through an
independent authorization process into OpenFGA or native kcp RBAC. It is intended
for fresh development clusters and architecture review. It does not establish a
production authorization contract or migrate existing grants.

For a plain-language explanation of the code, contracts, boundaries and
comparisons, read [WALKTHROUGH.md](WALKTHROUGH.md).

## What is implemented

- Experimental `core.platform-mesh.io/v1alpha1` AuthorizationGrant, with immutable
  account identity, canonical User subject, role and propagation; mutable
  Active/Revoked state; resolved workspace and reconciliation status.
- Opt-in account initialization/termination through intent. Creator grants are
  created once, retained when revoked, and cleaned up before workspace termination.
- Independent `security-operator authz` process with RBAC and OpenFGA projections.
  In the FGA profile the projection controller and authorization webhook run as
  separate deployments, permitting projection interruption experiments.
- UID-based projection ownership, overlapping grants, retry after an unknown FGA
  write outcome, stale Account UID rejection, and cleanup finalizers.
- Exact-path APIExportPolicy projection. Binding eligibility controls future API
  bindings; resource permissions have a separate lifecycle.
- Explicit headless Tilt profiles and a Go runner that compares actual API access
  with kcp access reviews and writes JSON, Markdown and JUnit evidence.

The existing default composition uses its existing permission writers. Select a
PoC profile explicitly. Never combine the legacy tuple writers with intent mode.

## Contract exercised by the experiment

```yaml
apiVersion: core.platform-mesh.io/v1alpha1
kind: AuthorizationGrant
metadata:
  name: example-reader
spec:
  accountRef:
    name: org-a
    uid: REPLACE_WITH_ACCOUNT_UID
  subject:
    kind: User
    name: reader
  roleRef: account-reader
  propagation: Local
  state: Active
```

The resource lives alongside the Account in its parent workspace. Its scope is
**the generated account workspace's contents**. Permissions on the Account object
in its parent workspace are governed independently by that parent's permissions.

| Role | Permissions |
|---|---|
| account-reader | Workspace entry; get/list/watch AccountInfo, immediate child Account objects, and HTTPBins |
| account-editor | Reader permissions plus create/update/patch/delete HTTPBins |

Both roles can create self access reviews. Neither permits Account mutation,
grant management, RBAC management or secret access. Administrators provision the
accounts and namespaces. Claims about safe user-driven account provisioning,
groups, service accounts, invitations or real OIDC identity mapping are outside
this experiment.

`Local` does not imply descendant workspace access. `Descendants` is implemented
by the FGA model and reported as UnsupportedCapability in RBAC. Grants are additive:
revoking one grant does not remove access independently supplied by another.

Status `Reconciled=True` means backend projection matches the current desired
state. It is not an access-cache convergence guarantee. Actual requests establish
access convergence. Revocation remains pending while projection is unavailable.

## Run

Run from the monorepo root:

```sh
task authz-poc:up PROFILE=authz-rbac
```

The up task uses the dedicated kind context `kind-platform-mesh-authz-rbac`.
Repeat the procedure with `authz-openfga` and `authz-baseline` in separate fresh
clusters. The shared Tilt credential export is refreshed by the active deployment;
the evidence collector verifies that it matches the requested profile's cluster.
Run one profile at a time because Tilt's credential export and local build paths
are shared. To repeat from an entirely fresh cluster, remove only the dedicated
PoC cluster you intend to recreate; the up task does not delete existing clusters.

Retained kind clusters consume Docker VM resources after Tilt stops. Stop idle
PoC control-plane containers when moving to the next profile; this preserves
their data.

If the PoC hostnames resolve to `127.0.0.1`, keep a gateway port-forward running
in a separate terminal. For the OpenFGA profile:

```sh
kubectl --context kind-platform-mesh-authz-openfga -n platform-mesh-system \
  port-forward service/platform-mesh-prerequisites-traefik 31000:8443
```

Use the matching context for other profiles. The hostname and TLS configuration
stay the same; the forward makes the gateway reachable from the host.

The `authz` process serves startup/liveness on `/healthz` and readiness on
`/readyz` at port 8090. These probes report process initialization; permission
projection is reported on grants. Configured fixture workspaces such as
`root:orgs:org-a` do not exist until the fixture task provisions them. Pending
reconciliation logs now include the workspace name: errors for `root:orgs` itself
must be investigated rather than attributed to missing fixtures.

All headless PoC profiles disable workspace authentication initialization and set
`--wait-workspace-auth-disabled=true` on platform-mesh-operator. Readiness still
checks infrastructure resources, but does not wait for the authentication
audience supplied by the omitted initializer. Normal deployments keep this check
enabled. The `platformmesh-ready` Tilt resource must finish before the provider
policy and provider kubeconfig export can run.

Once infrastructure and the HTTPBin provider are ready, use another terminal:

```sh
task authz-poc:demo PROFILE=authz-rbac
```

`demo` first waits for the provider export to publish HTTPBin, then provisions
two organizations, sibling/nested accounts and fixture namespaces,
explicitly binds the HTTPBin API into the organization workspaces and waits for
those APIBindings to become Bound, then resets only runner-owned grants and
executes the scenario file. Fixture
initialization/deletion budgets are 180 seconds after infrastructure readiness;
healthy permission convergence has a 30-second budget. Both shard profiles disable
webhook decision caching for this experiment. These are PoC budgets, not SLOs.

The default `cases-rbac.json` and `cases-openfga.json` exercise local access,
HTTPBin write boundaries, denied grant management, organization/descendant
isolation, overlapping grants, revocation and explicit inheritance. The baseline
records legacy creator and unassigned-user behavior without writing grants.
HTTPBin create probes use server-side dry run, so repeated authorization checks do
not create workloads.

The harness submits requests using synthetic users with `system:authenticated`;
it never forwards `system:masters`. It prefers SelfSubjectAccessReview. If a
revoked identity cannot create that review, it records the distinction and submits
an exact-subject SubjectAccessReview through the same target workspace as the
administrator. Transport errors and review evaluation errors are failures, never
successful denial results.

```sh
task authz-poc:validate PROFILE=authz-openfga EVIDENCE=contrib/poc/authz/results/fga-run-1
task authz-poc:report EVIDENCE=contrib/poc/authz/results/fga-run-1
```

Every case records expected/actual access in its scenario input and report, latest
conditions, duration, and classification. A defect makes the runner exit nonzero
while retaining the report. Evidence includes runtime images/digests, source
revision and shard authorization configuration. Credential files and evidence
outputs are ignored by Git. Do not apply the partial APIExport emitted by apigen
from a single CRD over the installed core export.

## Failure and lifecycle experiments

After fixtures exist, these commands operate only on the dedicated profile's
cluster and preserve their evidence under `results/<profile>-<experiment>`:

```sh
task authz-poc:experiment PROFILE=authz-openfga EXPERIMENT=outage
task authz-poc:experiment PROFILE=authz-openfga EXPERIMENT=restart
task authz-poc:experiment PROFILE=authz-openfga EXPERIMENT=rebuild
task authz-poc:experiment PROFILE=authz-rbac EXPERIMENT=restart
task authz-poc:experiment PROFILE=authz-rbac EXPERIMENT=recreate
```

- `outage`: stop FGA, verify denial and independent administrator access, restore
  FGA and verify recovery. A trap restores the deployment on failure.
- `restart`: stop projection while checks remain available, revoke a grant,
  demonstrate pending projection, restart and verify effective revocation.
- `rebuild`: replay persisted intent into a new empty PoC FGA store and repoint
  the check process; restore original process arguments afterwards. This is an
  engine reconstruction experiment, not a backend-switch migration.
- `recreate`: provision a disposable account, grant access, delete it, recreate
  the same name with a new UID and verify the former user's access does not return.

Two architecture checks still require a targeted scenario/configuration change:

1. **Provider MPP restriction.** In `root:providers:httpbin-provider`, save the
   HTTPBin APIExport configuration, enable `spec.maximalPermissionPolicy.local`,
   and bind `apis.kcp.io:binding:system:authenticated` to an explicit read-only
   HTTPBin ClusterRole. Use an editor HTTPBin-create probe with
   `expectedAllowed=false`. Preserve both API and SAR results and restore the
   export afterwards. A webhook allow must not bypass the provider restriction.
2. **Binding eligibility revocation.** Compare actual APIBinding creation for an
   exact allowed consumer with a consumer excluded from APIExportPolicy; then
   remove the allowed expression and try a new binding. Existing bindings and
   resource grants are not revoked by this operation. Record these independently.

Do not claim these checks passed based on role projection or direct FGA checks.
They must traverse the pinned kcp authorization chain. The example runner's
scenario format supports additional get and dry-run HTTPBin-create probes.

## Architecture-review package

Present the evidence using [PRESENTATION.md](PRESENTATION.md). Reviewers should be
able to trace every conclusion to a result row and its input manifest. Unrun
experiments remain **not tested**; unsupported capabilities are distinct from
implementation defects.

Known boundaries of this implementation:

- Runtime/API separation is exercised; the security-operator Go module and
  existing shared API package still contain legacy FGA dependencies and fields.
- Polling uses explicitly configured parent workspaces; the sample topology is
  bounded. A production controller would use multicluster engagement and watches.
- The PoC controller and initializer use administrator credentials. Grant
  management is restricted to trusted setup; least-privilege controller RBAC is
  follow-up work.
- Bootstrap-grant deletion revokes access and retains a finalizer until the owning
  Account is deleting. The bootstrap marker is safe against the PoC roles because
  those roles cannot mutate Accounts; administrators remain trusted.
- Arbitrary ProviderPermissions expressions and wildcard APIExportPolicy paths
  are outside the portable subset and must not be silently translated.
- Existing FGA-specific APIExports can remain installed; the native exercised
  core path must operate without their engine/controllers. This does not prove
  that every platform component is decoupled.
- Existing-installation migration, runtime backend switching, production cache
  behavior and production identity mapping are unvalidated.

## Local verification and generation

```sh
task authz-poc:test
go test ./operators/security-operator/internal/subroutine ./operators/security-operator/pkg/config ./operators/security-operator/cmd
go test ./operators/platform-mesh-operator/pkg/subroutines ./operators/platform-mesh-operator/internal/config
task build-security-operator
```

Grant CRDs/deepcopy are generated from the shared API types. Use the repository's
`generate-apis` and `generate-security-operator` tasks when changing the contract;
keep the deployed core APIResourceSchema and the experimental generated copy in
sync. The first implementation used the cached controller-gen and kcp apigen
sources because GitHub/tool downloads were unavailable.

See [VALIDATION.md](VALIDATION.md) for the checks actually completed in this session.
