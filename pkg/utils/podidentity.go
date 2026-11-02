package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
)

// podIdentityVersion prefixes the canonical label text so a future change to the
// recipe produces different identities instead of silently matching old ones.
const podIdentityVersion = "v1\n"

// PodIdentity returns the enforcement identity for a pod: a 128-bit fingerprint of
// the pod's labels, scoped to its namespace.
//
//	identity = hex(SHA-256("v1\n" + sorted "key=value\n" lines))[:32] + "@" + namespace
//
// Two pods in the same namespace with identical labels are selected by exactly the
// same NetworkPolicies, so they can safely share one eBPF program and map set. Any
// difference in labels yields a different identity. The pod name is deliberately not
// an input: it is chosen by whoever creates the pod and says nothing about which
// policies select it (see aws-network-policy-agent#327).
//
// Labels must come from the API server (pod informer or GET), never from the CNI
// request. Callers must not fall back to GetPodIdentifier when labels are unavailable.
//
// '=' and '\n' cannot appear in label keys or values, so the canonical text is
// unambiguous. The output is lowercase hex plus '@' and the namespace, which contains
// no '_' and therefore keeps bpffs pin filenames parseable by
// GetPodIdentifierFromBPFPinPath.
func PodIdentity(labels map[string]string, namespace string) string {
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	h := sha256.New()
	h.Write([]byte(podIdentityVersion))
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write([]byte{'='})
		h.Write([]byte(labels[k]))
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil)[:16]) + "@" + namespace
}
