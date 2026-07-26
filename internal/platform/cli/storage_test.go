package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestStorageOptionsResolveFromTheEnvironment covers the ordering that makes
// the environment safe to use: it fills what was not given, and never
// overrides what was.
//
// These cannot run in parallel — t.Setenv is process-wide.
func TestStorageOptionsResolveFromTheEnvironment(t *testing.T) {
	t.Run("an unset option comes from the environment", func(t *testing.T) {
		t.Setenv(EnvDeployment, "/srv/sesame")
		resolved := storageOptions{}.fromEnvironment()
		if resolved.Deployment != "/srv/sesame" {
			t.Fatalf("deployment = %q", resolved.Deployment)
		}
	})

	t.Run("an explicit option wins", func(t *testing.T) {
		// An operator debugging one command on a host that already exports
		// SESAME_DEPLOYMENT must be able to point it elsewhere without
		// unsetting anything. Preferring the environment would make the flag
		// they just typed a lie.
		t.Setenv(EnvDeployment, "/srv/sesame")
		resolved := storageOptions{Deployment: "./local"}.fromEnvironment()
		if resolved.Deployment != "./local" {
			t.Fatalf("the environment overrode an explicit flag: %q", resolved.Deployment)
		}
	})

	t.Run("the bare pair resolves too", func(t *testing.T) {
		t.Setenv(EnvFYLOBinary, "/usr/local/bin/fylo")
		t.Setenv(EnvFYLORoot, "/var/lib/sesame")
		resolved := storageOptions{}.fromEnvironment()
		if resolved.FYLOBinary != "/usr/local/bin/fylo" || resolved.FYLORoot != "/var/lib/sesame" {
			t.Fatalf("resolved %#v", resolved)
		}
	})

	t.Run("configured sees the environment", func(t *testing.T) {
		// configured() gates the usage error every command prints before it
		// opens storage. If it did not resolve, an environment-configured
		// deployment would be rejected as unconfigured.
		if (storageOptions{}).configured() {
			t.Fatal("empty options reported themselves configured")
		}
		t.Setenv(EnvDeployment, "/srv/sesame")
		if !(storageOptions{}).configured() {
			t.Fatal("an environment-configured deployment was reported unconfigured")
		}
	})

	t.Run("resolution is idempotent", func(t *testing.T) {
		// openStorage and configured both resolve, so this runs twice on the
		// same value in every command.
		t.Setenv(EnvDeployment, "/srv/sesame")
		once := storageOptions{}.fromEnvironment()
		if twice := once.fromEnvironment(); twice != once {
			t.Fatalf("resolving twice changed the result: %#v then %#v", once, twice)
		}
	})
}

// TestStorageFlagHelpNamesTheEnvironment: a developer who cannot find the
// variable will pass the flag forever. The help output is where they look.
func TestStorageFlagHelpNamesTheEnvironment(t *testing.T) {
	t.Parallel()

	_, _, stderr := runSAMLCommand(t)
	// The usage line lists subcommands; the flag help is printed on a parse
	// failure, which is the path a developer actually hits.
	_, _, flagHelp := runSAMLCommand(t, "provider-get", "--help")
	combined := stderr + flagHelp
	for _, variable := range []string{EnvDeployment, EnvFYLOBinary, EnvFYLORoot} {
		if !strings.Contains(combined, variable) {
			t.Errorf("the CLI help never mentions %s", variable)
		}
	}
}

// TestInitAndDoctorReadTheEnvironment.
//
// These two commands used to be the exceptions: every other command filled its
// deployment from SESAME_DEPLOYMENT, and these demanded the flag. That is
// backwards where it matters most — `init` is the command that decides what
// every later command will find, and a developer who has already exported the
// variable has no reason to expect to repeat it here.
//
// These cannot run in parallel — t.Setenv is process-wide.
func TestInitAndDoctorReadTheEnvironment(t *testing.T) {
	fylo := filepath.Join(t.TempDir(), "fylo")
	if err := os.WriteFile(fylo, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatalf("write a stand-in FYLO binary: %v", err)
	}

	t.Run("init takes the deployment and binary from the environment", func(t *testing.T) {
		deployment := filepath.Join(t.TempDir(), "deploy")
		t.Setenv(EnvDeployment, deployment)
		t.Setenv(EnvFYLOBinary, fylo)

		var stdout, stderr bytes.Buffer
		if code := runInit(nil, &stdout, &stderr); code != ExitSuccess {
			t.Fatalf("sesame init with no flags: exit %d\n%s", code, stderr.String())
		}
		var summary struct {
			Deployment string `json:"deployment"`
			FYLOBinary string `json:"fylo_binary"`
		}
		if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
			t.Fatalf("decode the init summary: %v", err)
		}
		if summary.Deployment != deployment || summary.FYLOBinary != fylo {
			t.Fatalf("init used %#v, not what the environment named", summary)
		}
	})

	t.Run("an explicit flag still wins", func(t *testing.T) {
		elsewhere := filepath.Join(t.TempDir(), "elsewhere")
		t.Setenv(EnvDeployment, filepath.Join(t.TempDir(), "from-env"))
		t.Setenv(EnvFYLOBinary, fylo)

		var stdout, stderr bytes.Buffer
		if code := runInit([]string{"--deployment", elsewhere}, &stdout,
			&stderr); code != ExitSuccess {
			t.Fatalf("sesame init --deployment: exit %d\n%s", code, stderr.String())
		}
		var summary struct {
			Deployment string `json:"deployment"`
		}
		if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
			t.Fatalf("decode the init summary: %v", err)
		}
		if summary.Deployment != elsewhere {
			t.Fatalf("the environment overrode an explicit --deployment: %q", summary.Deployment)
		}
	})

	t.Run("neither source means a usage error naming both", func(t *testing.T) {
		t.Setenv(EnvDeployment, "")
		t.Setenv(EnvFYLOBinary, "")

		var stdout, stderr bytes.Buffer
		if code := runInit(nil, &stdout, &stderr); code != ExitUsage {
			t.Fatalf("sesame init with nothing configured: exit %d", code)
		}
		// A developer who is missing the value looks here for what to set.
		for _, variable := range []string{EnvDeployment, EnvFYLOBinary} {
			if !strings.Contains(stderr.String(), variable) {
				t.Errorf("the init usage line never mentions %s:\n%s", variable, stderr.String())
			}
		}
	})

	t.Run("doctor takes the deployment from the environment", func(t *testing.T) {
		// diagnose reports on whatever directory it was given, so an
		// unreadable one still proves which path was resolved.
		missing := filepath.Join(t.TempDir(), "never-initialised")
		t.Setenv(EnvDeployment, missing)

		var stdout, stderr bytes.Buffer
		if code := runDoctor(context.Background(), nil, &stdout,
			&stderr); code == ExitUsage {
			t.Fatalf("sesame doctor with no flags reported a usage error\n%s", stderr.String())
		}
		var report doctorReport
		if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
			t.Fatalf("decode the doctor report: %v", err)
		}
		if report.Deployment != missing {
			t.Fatalf("doctor inspected %q, not what the environment named", report.Deployment)
		}
	})

	t.Run("doctor with nothing configured names the variable", func(t *testing.T) {
		t.Setenv(EnvDeployment, "")

		var stdout, stderr bytes.Buffer
		if code := runDoctor(context.Background(), nil, &stdout,
			&stderr); code != ExitUsage {
			t.Fatalf("sesame doctor with nothing configured: exit %d", code)
		}
		if !strings.Contains(stderr.String(), EnvDeployment) {
			t.Errorf("the doctor usage line never mentions %s:\n%s", EnvDeployment, stderr.String())
		}
	})
}

// TestAnExplicitModeSuppressesTheOtherFromTheEnvironment.
//
// The deployment directory and the bare binary/root pair are alternatives, and
// presenting both is refused. That refusal used to fire on a combination
// nobody chose: a host application passing --deployment on a machine whose
// environment exported FYLO_BINARY got a conflict between something it asked
// for and something it never asked about. The example host server hit exactly
// this, which is how it was found.
//
// These cannot run in parallel — t.Setenv is process-wide.
func TestAnExplicitModeSuppressesTheOtherFromTheEnvironment(t *testing.T) {
	t.Run("an explicit deployment ignores FYLO_* in the environment", func(t *testing.T) {
		t.Setenv(EnvFYLOBinary, "/usr/local/bin/fylo")
		t.Setenv(EnvFYLORoot, "/var/lib/fylo")

		resolved := storageOptions{Deployment: "./deploy"}.fromEnvironment()
		if resolved.FYLOBinary != "" || resolved.FYLORoot != "" {
			t.Fatalf("the environment forced a conflicting mode: %#v", resolved)
		}
	})

	t.Run("an explicit FYLO pair ignores SESAME_DEPLOYMENT", func(t *testing.T) {
		t.Setenv(EnvDeployment, "/srv/sesame")

		resolved := storageOptions{
			FYLOBinary: "/usr/local/bin/fylo", FYLORoot: "/var/lib/fylo",
		}.fromEnvironment()
		if resolved.Deployment != "" {
			t.Fatalf("the environment forced a conflicting mode: %#v", resolved)
		}
	})

	t.Run("the environment still completes a half-given FYLO pair", func(t *testing.T) {
		// Choosing the bare mode explicitly is not the same as spelling out
		// both halves of it.
		t.Setenv(EnvFYLORoot, "/var/lib/fylo")

		resolved := storageOptions{FYLOBinary: "/usr/local/bin/fylo"}.fromEnvironment()
		if resolved.FYLORoot != "/var/lib/fylo" {
			t.Fatalf("the environment did not complete the pair: %#v", resolved)
		}
	})

	t.Run("an environment that names both is still a conflict", func(t *testing.T) {
		// Nothing was chosen here, so there is no explicit intent to honour
		// and the deployment must not silently win.
		t.Setenv(EnvDeployment, "/srv/sesame")
		t.Setenv(EnvFYLOBinary, "/usr/local/bin/fylo")

		resolved := storageOptions{}.fromEnvironment()
		if resolved.Deployment == "" || resolved.FYLOBinary == "" {
			t.Fatalf("an ambiguous environment was silently resolved: %#v", resolved)
		}
	})
}
