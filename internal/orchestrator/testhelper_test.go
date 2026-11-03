package orchestrator

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// freshForgeProject: see the identical helper in internal/runner. Each test
// gets its own isolated project copy so parallel test binaries don't clobber
// a shared test/Exploit.t.sol.
func freshForgeProject(t *testing.T, base string) string {
	t.Helper()
	dst := t.TempDir()
	if b, err := os.ReadFile(filepath.Join(base, "foundry.toml")); err == nil {
		os.WriteFile(filepath.Join(dst, "foundry.toml"), b, 0o644)
	}
	if out, err := exec.Command("cp", "-r", filepath.Join(base, "src"), filepath.Join(dst, "src")).CombinedOutput(); err != nil {
		t.Fatalf("copy src: %v: %s", err, out)
	}
	if err := os.Symlink(filepath.Join(base, "lib"), filepath.Join(dst, "lib")); err != nil {
		t.Fatalf("symlink lib: %v", err)
	}
	return dst
}
