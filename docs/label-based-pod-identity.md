# Label-based pod identity: change map

Branch: `dev/label-based-pod-identity`, based on upstream `main` @ `4bf96cf`.
Design: [Implementation Plan to support Standalone Pods in NPA, Option 1](https://chorus.aws.dev/doc/A9K6NHyh4CCv/Implementation-Plan-to-support-Standalone-Pods-in-NPA#option-1-label-based-identity).
Fixes: #327, #671, #616, #613; #691 for NetworkPolicy.

**NPA-only. No NPC or CRD change.** NPA computes the identity from node-local pod labels.
`PolicyEndpoint.Spec.PodSelector` gives the fast path; `Spec.PodSelectorEndpoints` stays the
authoritative selection.

```
identity = hex(SHA-256("v1\n" + sorted "key=value\n" lines))[:32] + "@" + namespace
```

Line numbers below refer to `4bf96cf`.

## Status

| # | Change | State |
|---|---|---|
| 1 | `utils.PodIdentity` + tests | **Done** (`pkg/utils/podidentity.go`) |
| 2 | Node-scoped pod cache | TODO |
| 3 | `podidentity.Resolver` (labels → identity, pod → identity store) | TODO |
| 4 | Replace `GetPodIdentifier` at every call site | TODO |
| 5 | Bind policies only for local pods + selector match | TODO |
| 6 | CNI ADD fast path via `Spec.PodSelector` | TODO |
| 7 | Label-change handling | TODO |
| 8 | Persist pod → identity across restart | TODO |
| 9 | Pin migration name-prefix → label identity | TODO |
| 10 | CLI `show` identity → labels | TODO |

## 1. Identity function: done

`pkg/utils/podidentity.go`. Golden values match the design doc table. The output contains no
`_`, so it round-trips through `GetBPFPinPathFromPodIdentifier` / `GetPodIdentifierFromBPFPinPath`
(`pkg/utils/utils.go:207`). `GetPodIdentifier` stays only for the pin migration (step 9) and is
deleted once the migration window closes.

## 2. Node-scoped pod cache

**Required, not optional.** `mgr.GetClient()` reading `corev1.Pod` would otherwise start a
cluster-wide pod informer on every node.

- `pkg/config/runtime_config.go:66` `BuildRuntimeOptions`: add
  ```go
  Cache: cache.Options{ByObject: map[client.Object]cache.ByObject{
      &corev1.Pod{}: {Field: fields.OneTermEqualSelector("spec.nodeName", nodeName)},
  }},
  ```
  Optionally add a `cache.TransformFunc` that strips everything except
  `metadata.{name,namespace,uid,labels}` and `spec.nodeName` to keep memory flat.
- `main.go:112`: needs the **node name**, but NPA currently only reads the node IP from IMDS.
  Source it from `MY_NODE_NAME` (downward API). **Verify** the aws-node DaemonSet sets it on the
  `aws-network-policy-agent` container in the vpc-cni chart and the Auto Mode manifest.
- RBAC: pods `get/list/watch` on the aws-node ClusterRole. **Verify** in both the vpc-cni chart
  and Auto Mode.

## 3. New package `pkg/podidentity`

```go
type Resolver interface {
    // Identity reads labels from the node-scoped cache (falls back to a live GET) and
    // returns PodIdentity. ok=false means labels are unavailable; the caller must apply
    // the mode default and MUST NOT fall back to the name prefix.
    Identity(ctx context.Context, pod types.NamespacedName) (id string, labels map[string]string, ok bool, err error)
    // Recorded returns the identity saved at CNI ADD. Used by CNI DEL and cleanup, where
    // the pod and its labels may already be gone.
    Recorded(pod types.NamespacedName) (string, bool)
    Record(pod types.NamespacedName, id string) error
    Forget(pod types.NamespacedName) error
}
```

The store behind `Record`/`Recorded` must survive agent restart (step 8).

## 4. Call sites of `GetPodIdentifier` (15)

Every call becomes `resolver.Recorded(pod)` (paths where the pod may be gone) or
`resolver.Identity(ctx, pod)` (paths where it is live).

| File:line | Path | Replace with |
|---|---|---|
| `pkg/rpc/rpc_handler.go:83` | CNI ADD | `Identity` → `Record`. See step 6. |
| `pkg/rpc/rpc_handler.go:198` | CNI DEL | `Recorded` → `Forget` after `DeleteBPFProbes` |
| `controllers/policyendpoints_controller.go:208` | PE delete: scrub map | `Recorded` |
| `controllers/policyendpoints_controller.go:281` | enforcement status loop | `Recorded` |
| `controllers/policyendpoints_controller.go:478` | `cleanupPod` | `Recorded` |
| `controllers/policyendpoints_controller.go:791` | `deriveTargetPods` | See step 5 |
| `controllers/clusterpolicyendpoints_controller.go:157` | CPE delete: scrub map | `Recorded` |
| `controllers/clusterpolicyendpoints_controller.go:502` | `deriveClusterPolicyTargetPods` | See step 5 |
| `controllers/clusterpolicyendpoints_controller.go:533` | `cleanupClusterPolicyPod` | `Recorded` |
| `controllers/shared.go:40` | `trackFailedCleanups` | `Recorded` |
| `controllers/shared.go:61` | `attachProbesForIdentifier` | `Recorded`. Update the comment: replicas now share an identity because they share labels, not a name prefix. |
| `pkg/utils/policy_utils.go:23` | `GetPodListToBeCleanedUp` | Pass a `func(NamespacedName) string` resolver in; `utils` must not import `podidentity`. |
| `pkg/ebpf/legacy_pin_migration.go:63,78` | pin migration | See step 9 |
| `pkg/utils/utils.go:177` | definition | Keep for migration only |

Signatures that take `podIdentifier string` (`BpfClient`, `UpdateEbpfMaps`, `HasBPFContext`, …)
don't change. Only what gets passed into them does.

## 5. Policy binding: local pods only, with a selector match

`deriveTargetPods` (`controllers/policyendpoints_controller.go:776`), today:

```go
podIdentifier := utils.GetPodIdentifier(pod.Name, pod.Namespace)
clusterwidePodIdentifiers[podIdentifier] = true
if nodeIP.Equal(...) { targetPods = append(...); podIdentifiers[podIdentifier] = true }
utils.UpdatePodIdentifierToPolicyEndpointMap(..., podIdentifier, parentPEList) // runs for EVERY node's pods
```

New:

```go
if !nodeIP.Equal(net.ParseIP(string(pod.HostIP))) {
    continue // remote pods: can't hash their labels, and don't need to
}
id, labels, ok, err := r.resolver.Identity(ctx, nn)
if !ok || err != nil { continue } // retried on the next reconcile / informer event
if !selectorMatches(policyEndpoint.Spec.PodSelector, labels) {
    continue // stale PE still listing a relabeled pod
}
targetPods = append(targetPods, ...)
podIdentifiers[id] = true
utils.UpdatePodIdentifierToPolicyEndpointMap(&r.podIdentifierToPolicyEndpointMap, ..., id, parentPEList)
```

Effects:
- `podIdentifierToPolicyEndpointMap` now only holds local identities, which **fixes #613**.
- `clusterwidePodIdentifiers` / `networkPolicyToPodIdentifierMap` (`:737-:770`) collapse to local
  scope. Simplify or remove `DeriveStalePodIdentifiers` along with them.
- `selectorMatches`: `metav1.LabelSelectorAsSelector`. **Verify** whether NPC writes `nil` or `{}`
  for `podSelector: {}`. `default-deny` must match every pod.

Apply the same change to `deriveClusterPolicyTargetPods` (`clusterpolicyendpoints_controller.go:495`),
minus the selector check, because `ClusterPolicyEndpointSpec` has no selector.

## 6. CNI ADD fast path (`EnforceNpToPod`, `pkg/rpc/rpc_handler.go:51`)

```go
id, labels, ok, err := s.resolver.Identity(ctx, nn)
if !ok {
    // No labels (cache miss + GET failed): mode default, never the name prefix.
    return s.applyDefaultState(...)
}
s.resolver.Record(nn, id)
isFirst, err := ebpf.AttacheBPFProbes(nn, id, ...)

// NEW: bind matching PEs before the cache check, so the first pod of an identity
// is enforced from its first packet (#691), not after the PE reconcile.
s.policyReconciler.BindMatchingPolicyEndpoints(ctx, id, nn.Namespace, labels)

policiesAvailableInLocalCache := s.policyReconciler.ArePoliciesAvailableInLocalCache(id)
... rest unchanged, with podIdentifier -> id
```

`BindMatchingPolicyEndpoints` (new, `policyendpoints_controller.go`): list PEs in the namespace
from the cache, keep those whose `Spec.PodSelector` matches `labels`, and
`UpdatePodIdentifierToPolicyEndpointMap(id, matchingPENames)`.

Cluster policies: no selector, so no fast path. The pod gets the mode default until the CPE
reconcile, which is today's behavior for uniquely named pods.

**Race to verify:** CNI ADD can arrive before the node-scoped informer sees the pod. The live
GET fallback covers this; measure how often it happens at QRT scale.

## 7. Label change

Add a `Watches(&corev1.Pod{}, ...)` (with a label-change predicate) to
`PolicyEndpointsReconciler.SetupWithManager` (`:818`):

1. Compute `newID`. If it equals `Recorded(pod)`, do nothing.
2. `AttacheBPFProbes(pod, newID)`, bind matching PEs, program the maps.
3. Atomically replace the tc filter on the pod's veth (old prog → new prog).
4. `Record(pod, newID)`; `DeleteBPFProbes(pod, oldID)`, which frees the old maps if this was the last pod.

This needs an ebpf-client primitive to **re-point** a pod from one identity to another without a
detach gap. Check whether `AttacheBPFProbes` replacing the filter on an existing handle is
already atomic.

## 8. Persisting pod → identity

Options (open question in the design doc):
- **Rebuild at startup (preferred):** after the cache syncs, recompute from labels for every local
  pod. No new on-disk state. Gap: pods deleted while the agent was down leave pins behind with
  no live pod. There is no orphan-pin sweep on `main` today, so one has to be added.
- State file under `/var/run/aws-node/`: survives restart even if the API server is unreachable.
- Pinned BPF map: most robust, most code.

## 9. Upgrade pin migration

`pkg/ebpf/legacy_pin_migration.go` runs before the manager starts and reads pod names from the
CNI IPAM state file, which has **no labels**. The label migration therefore has to run **after the
pod cache syncs**:

1. For each local pod: `old = GetPodIdentifier(name, ns)`, `new = PodIdentity(labels, ns)`.
2. Group by `old`. If every pod in the group maps to the same `new`, rename the pin family
   (`renamePinFamily`). Otherwise (the collision case this change fixes), give each extra `new`
   fresh pins and reprogram it.
3. Write a `formatV3` marker; keep `formatV2MarkerPath` handling for nodes that skip a version.

Until the migration finishes, keep the old pins attached, so pods are never left unenforced.

## 10. CLI

`cmd/cli`: `show` prints `identity → {labels, local pods}` so oncall can see what an opaque hash means.

## Tests to add

- `deriveTargetPods`: a remote pod adds nothing to the map; a relabeled pod still listed in a
  stale PE is not bound.
- `EnforceNpToPod`: `db-evil` (`app=evil`) next to `db-0` (`app=db`) gets the default, not db rules
  (the Robosec repro as a unit test). A first pod with matching labels gets `POLICIES_APPLIED`.
- Labels unavailable → mode default, and `GetPodIdentifier` is never consulted.
- Migration: same-labels group renames; colliding group splits.
- e2e: Robosec steps in `test/`; #616 and #671 repros; #691 latency (CNI ADD → enforced).

## Trade-offs carried

- StatefulSet `statefulset.kubernetes.io/pod-name` (and `apps.kubernetes.io/pod-index`) and
  indexed Job `batch.kubernetes.io/job-completion-index` labels give one identity per pod. The
  fast path in step 6 removes the enforcement delay; the remaining cost is map count.
- Rollouts briefly double identities (old and new `pod-template-hash`).
- Downgrade reintroduces the name-prefix collision; document this in the rollback guidance.
