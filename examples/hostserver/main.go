// Command hostserver shows how a developer's own HTTP server owns its
// listener while SESAME runs as a supervised subprocess behind the Go SDK.
//
// SESAME opens no port. The host owns routing, TLS, and middleware; the
// authorization decision stays in the engine, and the middleware only
// enforces it. The OIDC wire routes in oidc.go are mounted on this same
// host-owned mux.
//
//	go run ./examples/hostserver \
//	  --sesame /path/to/sesame \
//	  --deployment /path/to/deploy \
//	  --addr 127.0.0.1:8443 \
//	  --tls-cert cert.pem --tls-key key.pem
//
// TLS is the host's job, not the engine's. Serve https whenever the issuer is
// https — which OpenID Connect requires of a real provider, and which the
// conformance suite therefore requires too. See docs/CONFORMANCE.md.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/d31ma/sesame/clients/go/sesame"
)

func main() {
	binary := flag.String("sesame", "sesame", "path to the SESAME executable")
	deployment := flag.String("deployment", "", "deployment directory created by sesame init")
	fyloBinary := flag.String("fylo-binary", "", "path to the pinned FYLO executable")
	fyloRoot := flag.String("fylo-root", "", "path to the exclusively owned FYLO data root")
	address := flag.String("addr", "127.0.0.1:8080", "host listener address")
	tenantName := flag.String("tenant", "example", "tenant to bootstrap on startup")
	tlsCert := flag.String("tls-cert", "", "PEM certificate; serves https when set with --tls-key")
	tlsKey := flag.String("tls-key", "", "PEM private key for --tls-cert")
	// Seeding exists for conformance and interoperability runs, which need a
	// client and a password they can actually use. It is deliberately explicit:
	// a host that silently created a credentialed account on every boot would
	// be a very bad example to copy.
	seedRedirects := flag.String("seed-client-redirects", "",
		"comma-separated redirect URIs; registers a test client and prints its credentials")
	seedPassword := flag.String("seed-password", "",
		"password to set on the bootstrapped administrator, for test runs only")
	flag.Parse()

	if (*tlsCert == "") != (*tlsKey == "") {
		log.Fatal("--tls-cert and --tls-key must be given together")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	client, err := sesame.Start(ctx, sesame.Options{
		Binary:     *binary,
		Deployment: *deployment,
		FYLOBinary: *fyloBinary,
		FYLORoot:   *fyloRoot,
		Stderr:     os.Stderr,
	})
	if err != nil {
		log.Fatalf("start sesame: %v", err)
	}
	defer client.Close()

	if status, reason, err := client.Readiness(ctx); err != nil || status != "ok" {
		log.Fatalf("sesame is not ready: status=%q reason=%q err=%v", status, reason, err)
	}

	// Converge the deployment to one administrator, then keep serving. This
	// is safe to run on every boot: an unchanged deployment appends nothing.
	admin, err := client.AdminBootstrap(ctx, *tenantName, sesame.PrincipalIdentifier{
		Namespace: "email",
		Value:     "admin@example.invalid",
	})
	if err != nil {
		log.Fatalf("bootstrap administrator: %v", err)
	}
	log.Printf("tenant %s administrator %s ready", admin.Tenant.ID, admin.Administrator.ID)

	if *seedPassword != "" {
		if err := client.SetPassword(ctx, admin.Administrator.ID, *seedPassword); err != nil {
			log.Fatalf("seed the administrator password: %v", err)
		}
	}
	if *seedRedirects != "" {
		registered, err := client.ClientRegister(ctx, admin.Tenant.ID, "conformance",
			"confidential", strings.Split(*seedRedirects, ","),
			[]string{"profile", "offline_access"}, "first_party", nil)
		if err != nil {
			log.Fatalf("seed the conformance client: %v", err)
		}
		// Printed as one JSON line on stdout so a runner can read it without
		// parsing the log. The secret is returned exactly once, by design.
		if err := json.NewEncoder(os.Stdout).Encode(map[string]any{
			"tenant_id":     admin.Tenant.ID,
			"principal_id":  admin.Administrator.ID,
			"client_id":     registered.Client.ID,
			"client_secret": registered.Secret,
		}); err != nil {
			log.Fatalf("write the seeded credentials: %v", err)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(writer http.ResponseWriter, request *http.Request) {
		status, reason, err := client.Readiness(request.Context())
		if err != nil || status != "ok" {
			writeJSON(writer, http.StatusServiceUnavailable, map[string]any{
				"status": status,
				"reason": reason,
			})
			return
		}
		writeJSON(writer, http.StatusOK, map[string]any{"status": status})
	})

	// The protected route delegates the decision to SESAME. The host maps
	// its own route to an action and resource; it never interprets policy.
	mux.Handle("GET /documents/{id}", authorize(client, admin.Tenant.ID, "doc:read", func(request *http.Request) string {
		return "project:" + request.PathValue("id")
	}, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writeJSON(writer, http.StatusOK, map[string]any{"document": request.PathValue("id")})
	})))

	// The OIDC wire routes live on this same mux: SESAME still opens no port.
	registerOIDCRoutes(mux, client, admin.Tenant.ID)

	server := &http.Server{
		Addr:              *address,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownContext)
	}()

	scheme := "http"
	serve := server.ListenAndServe
	if *tlsCert != "" {
		scheme = "https"
		serve = func() error { return server.ListenAndServeTLS(*tlsCert, *tlsKey) }
	}
	log.Printf("listening on %s://%s", scheme, *address)
	if err := serve(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("serve: %v", err)
	}
}

// authorize asks SESAME whether the caller may perform one action on one
// resource. The principal arrives here already authenticated by the host;
// SESAME's authentication slice will replace this header with a session.
func authorize(
	client *sesame.Client,
	tenantID string,
	action string,
	resourceOf func(*http.Request) string,
	next http.Handler,
) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		principalID := request.Header.Get("X-Principal-Id")
		if principalID == "" {
			writeJSON(writer, http.StatusUnauthorized, map[string]any{"error": "missing principal"})
			return
		}

		decision, err := client.Decide(request.Context(), sesame.DecisionRequest{
			TenantID:    tenantID,
			PrincipalID: principalID,
			Action:      action,
			Resource:    resourceOf(request),
		}, nil)
		if err != nil {
			// Fail closed: an unavailable decision is never an implicit allow.
			log.Printf("decision failed: %v", err)
			writeJSON(writer, http.StatusForbidden, map[string]any{"error": "decision unavailable"})
			return
		}
		if decision.Decision != "allow" {
			writeJSON(writer, http.StatusForbidden, map[string]any{
				"error":          "forbidden",
				"reason_code":    decision.ReasonCode,
				"decision_id":    decision.DecisionID,
				"policy_version": decision.PolicyVersion,
			})
			return
		}
		next.ServeHTTP(writer, request)
	})
}

func writeJSON(writer http.ResponseWriter, status int, body any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	if err := json.NewEncoder(writer).Encode(body); err != nil {
		fmt.Fprintf(os.Stderr, "encode response: %v\n", err)
	}
}
