package runner

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// freshForgeProject copies the base project (SENTINELX_PROJECT) into an
// isolated temp dir — foundry.toml + src/ copied, lib/ symlinked (forge-std
// is large and read-only, so a symlink is enough). This gives each test its
// OWN project, mirroring how the RunnerFactory hands each concurrent task an
// isolated sandbox in production. Without this, parallel tests writing the
// same test/Exploit.t.sol into one shared project clobber each other.
func freshForgeProject(t *testing.T, base string) string {
	t.Helper()
	dst := t.TempDir()
	// foundry.toml
	if b, err := os.ReadFile(filepath.Join(base, "foundry.toml")); err == nil {
		os.WriteFile(filepath.Join(dst, "foundry.toml"), b, 0o644)
	}
	// src/ (copy, so each project is self-contained)
	if out, err := exec.Command("cp", "-r", filepath.Join(base, "src"), filepath.Join(dst, "src")).CombinedOutput(); err != nil {
		t.Fatalf("copy src: %v: %s", err, out)
	}
	// lib/ (symlink — read-only dependencies, avoids a heavy copy)
	if err := os.Symlink(filepath.Join(base, "lib"), filepath.Join(dst, "lib")); err != nil {
		t.Fatalf("symlink lib: %v", err)
	}
	return dst
}
