package podidentity

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/types"
)

// SnapshotPath is where the agent publishes which labels and pods each identity on the
// node stands for. Identities are opaque hashes; this is what lets the CLI print them.
const SnapshotPath = "/var/run/aws-node/npa-pod-identities.json"

// snapshotInterval is how often a changed snapshot is written.
const snapshotInterval = 10 * time.Second

// IdentityInfo is one identity in the snapshot.
type IdentityInfo struct {
	// Labels the identity is the hash of. Nil for an isolated identity (labels unavailable).
	Labels map[string]string `json:"labels"`
	// Pods attached to it, as namespace/name.
	Pods []string `json:"pods"`
}

// Snapshot records identity -> labels and pods, and writes it to a file in the background.
// It is diagnostics only: enforcement never reads it. The zero value is not usable; use
// NewSnapshot.
type Snapshot struct {
	path string

	mu      sync.Mutex
	labels  map[string]map[string]string
	podToID map[types.NamespacedName]string
	dirty   bool
}

// NewSnapshot returns a snapshot that writes to path.
func NewSnapshot(path string) *Snapshot {
	return &Snapshot{
		path:    path,
		labels:  map[string]map[string]string{},
		podToID: map[types.NamespacedName]string{},
	}
}

// Record notes that pod is attached to podIdentifier. podLabels is nil for an isolated
// identity. Safe on a nil Snapshot.
func (s *Snapshot) Record(pod types.NamespacedName, podIdentifier string, podLabels map[string]string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.podToID[pod] = podIdentifier
	if _, known := s.labels[podIdentifier]; !known || podLabels != nil {
		s.labels[podIdentifier] = podLabels
	}
	s.dirty = true
}

// Forget drops a deleted pod. Safe on a nil Snapshot.
func (s *Snapshot) Forget(pod types.NamespacedName) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.podToID[pod]; ok {
		delete(s.podToID, pod)
		s.dirty = true
	}
}

// Identities returns the current snapshot contents.
func (s *Snapshot) Identities() map[string]IdentityInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.identitiesLocked()
}

func (s *Snapshot) identitiesLocked() map[string]IdentityInfo {
	out := map[string]IdentityInfo{}
	for pod, podIdentifier := range s.podToID {
		info := out[podIdentifier]
		info.Labels = s.labels[podIdentifier]
		info.Pods = append(info.Pods, pod.String())
		out[podIdentifier] = info
	}
	for podIdentifier, info := range out {
		sort.Strings(info.Pods)
		out[podIdentifier] = info
	}
	// Labels of identities no pod uses any more are dropped.
	for podIdentifier := range s.labels {
		if _, used := out[podIdentifier]; !used {
			delete(s.labels, podIdentifier)
		}
	}
	return out
}

// Start writes the snapshot whenever it changed, until ctx is done. It implements
// manager.Runnable.
func (s *Snapshot) Start(ctx context.Context) error {
	ticker := time.NewTicker(snapshotInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := s.flush(); err != nil {
				log().Debugf("Writing pod identity snapshot failed: %v", err)
			}
		}
	}
}

// NeedLeaderElection implements manager.LeaderElectionRunnable.
func (s *Snapshot) NeedLeaderElection() bool {
	return false
}

func (s *Snapshot) flush() error {
	s.mu.Lock()
	if !s.dirty {
		s.mu.Unlock()
		return nil
	}
	data, err := json.MarshalIndent(s.identitiesLocked(), "", "  ")
	s.dirty = false
	s.mu.Unlock()
	if err != nil {
		return err
	}
	if err := writeFileAtomic(s.path, data); err != nil {
		s.mu.Lock()
		s.dirty = true
		s.mu.Unlock()
		return err
	}
	return nil
}

func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// ReadSnapshot reads a snapshot file written by the agent.
func ReadSnapshot(path string) (map[string]IdentityInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out map[string]IdentityInfo
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return out, nil
}
