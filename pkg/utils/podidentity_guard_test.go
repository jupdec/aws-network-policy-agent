package utils

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Enforcement identity comes from labels (PodIdentity). A name-prefix identifier would let
// a pod pick another workload's rules by choosing its name, so production code must not
// derive one. The pin migration from the older "-" separator still needs the name-prefix
// form, to find the pins an older agent left.
func TestNoProductionCallersOfGetPodIdentifier(t *testing.T) {
	allowed := map[string]bool{
		filepath.Join("pkg", "utils", "utils.go"):               true, // the definitions
		filepath.Join("pkg", "ebpf", "legacy_pin_migration.go"): true,
	}
	root := filepath.Join("..", "..")
	var offenders []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		if info.IsDir() {
			if rel == "test" || rel == "vendor" || strings.HasPrefix(info.Name(), ".") && rel != "." {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") || allowed[rel] {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(data), "GetPodIdentifier(") {
			offenders = append(offenders, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(offenders) > 0 {
		t.Errorf("production code derives a name-prefix pod identifier; use the label identity instead: %v", offenders)
	}
}
