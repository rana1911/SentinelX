// Package fetchrepo prepares a Foundry project from a user-supplied source:
// a GitHub URL (cloned) or a local path. It locates the directory that holds
// foundry.toml and ensures forge-std is present (installing it if the repo
// didn't vendor it), so the audit pipeline gets a buildable project.
//
// SECURITY: the returned project is BUILT and EXECUTED by the audit (forge
// compiles and runs code from it, plus AI-written exploits). That is
// untrusted code. Run the server behind a sandbox (container/VM) before
// exposing it to arbitrary repos. This package clones and locates only; it
// does not sandbox.
package fetchrepo

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Prepared is a ready-to-audit project.
type Prepared struct {
	Dir     string // directory containing foundry.toml
	Root    string // top-level temp dir to remove when done ("" for local paths)
	Cloned  bool
	Message string // human note about what was prepared
}

// Cleanup removes the clone (no-op for local paths).
func (p *Prepared) Cleanup() {
	if p.Root != "" {
		os.RemoveAll(p.Root)
	}
}

var githubURL = regexp.MustCompile(`^(https://github\.com/|git@github\.com:)[\w.-]+/[\w.-]+?(\.git)?/?$`)

// IsGitHubURL reports whether src looks like a GitHub repo URL.
func IsGitHubURL(src string) bool {
	return githubURL.MatchString(strings.TrimSpace(src))
}

// Logf is an optional progress sink.
type Logf func(string)

func (l Logf) log(format string, a ...any) {
	if l != nil {
		l(fmt.Sprintf(format, a...))
	}
}

// Prepare resolves src into a buildable Foundry project.
func Prepare(ctx context.Context, src string, solc string, log Logf) (*Prepared, error) {
	src = strings.TrimSpace(src)
	var base string
	p := &Prepared{}

	switch {
	case IsGitHubURL(src):
		dst, err := os.MkdirTemp("", "exploitforge-repo-")
		if err != nil {
			return nil, err
		}
		p.Root = dst
		p.Cloned = true
		log.log("cloning %s", src)
		if err := run(ctx, 180*time.Second, "", "git", "clone", "--depth", "1", "--recurse-submodules", src, dst); err != nil {
			p.Cleanup()
			return nil, fmt.Errorf("git clone failed: %w", err)
		}
		base = dst
	case src == "":
		return nil, fmt.Errorf("no repository provided")
	default:
		// Local path (for testing / trusted use).
		abs, err := filepath.Abs(src)
		if err != nil {
			return nil, err
		}
		if fi, err := os.Stat(abs); err != nil || !fi.IsDir() {
			return nil, fmt.Errorf("not a directory: %s", src)
		}
		base = abs
	}

	proj, err := findFoundryProject(base)
	if err != nil {
		p.Cleanup()
		return nil, err
	}
	p.Dir = proj

	// Ensure forge-std exists; many repos use it and rely on `forge install`.
	if _, err := os.Stat(filepath.Join(proj, "lib", "forge-std")); err != nil {
		log.log("installing forge-std (not vendored in the repo)")
		if err := ensureForgeStd(ctx, proj); err != nil {
			p.Cleanup()
			return nil, fmt.Errorf("could not provision forge-std: %w", err)
		}
	}

	// Sanity: the project must build.
	log.log("building project")
	args := []string{"build"}
	if solc != "" {
		args = append(args, "--use", solc)
	}
	if err := run(ctx, 240*time.Second, proj, "forge", args...); err != nil {
		p.Cleanup()
		return nil, fmt.Errorf("forge build failed — is this a Foundry project with compiling sources? %w", err)
	}

	p.Message = "prepared " + filepath.Base(proj)
	return p, nil
}

// findFoundryProject returns the directory holding foundry.toml, searching the
// root then one level of subdirectories (monorepos often nest it).
func findFoundryProject(base string) (string, error) {
	if _, err := os.Stat(filepath.Join(base, "foundry.toml")); err == nil {
		return base, nil
	}
	entries, _ := os.ReadDir(base)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		cand := filepath.Join(base, e.Name())
		if _, err := os.Stat(filepath.Join(cand, "foundry.toml")); err == nil {
			return cand, nil
		}
	}
	return "", fmt.Errorf("no foundry.toml found (not a Foundry project)")
}

// ensureForgeStd installs forge-std into lib/. forge install needs a git repo,
// so init one if the source isn't already versioned.
func ensureForgeStd(ctx context.Context, proj string) error {
	if _, err := os.Stat(filepath.Join(proj, ".git")); err != nil {
		if err := run(ctx, 20*time.Second, proj, "git", "init", "-q"); err != nil {
			return err
		}
		run(ctx, 20*time.Second, proj, "git", "add", "-A")
		run(ctx, 20*time.Second, proj, "git", "-c", "user.email=a@b.c", "-c", "user.name=ef", "commit", "-qm", "init")
	}
	// Prefer forge install; fall back to a direct clone into lib/.
	if err := run(ctx, 120*time.Second, proj, "forge", "install", "foundry-rs/forge-std", "--no-commit"); err == nil {
		return nil
	}
	return run(ctx, 120*time.Second, proj, "git", "clone", "--depth", "1",
		"https://github.com/foundry-rs/forge-std", filepath.Join(proj, "lib", "forge-std"))
}

func run(ctx context.Context, timeout time.Duration, dir, name string, args ...string) error {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, name, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if len(msg) > 500 {
			msg = msg[len(msg)-500:]
		}
		return fmt.Errorf("%s %s: %v\n%s", name, strings.Join(args, " "), err, msg)
	}
	return nil
}
