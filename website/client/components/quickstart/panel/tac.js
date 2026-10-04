import { SDK_LANGUAGES } from '../../../shared/scripts/facts.js'

// The same question on each surface: may this principal perform this action,
// and why not. `deny_no_grant` is what an ungranted principal actually gets
// back, so the example shows a denial rather than a flattering allow.
//
// Over HTTP the principal asks about itself with its own session. The Go
// snippet hosts the engine directly and names no deployment: the package
// omits the flag when the option is absent, so the engine resolves
// SESAME_DEPLOYMENT out of the environment it inherits.
const SNIPPETS = {
  HTTP: `# ty serve app runs the Yon host. The session comes from
# POST /api/v1/authn/complete.
curl -s http://127.0.0.1:8080/api/v1/authorize/decide \\
  -H 'Content-Type: application/json' \\
  -H "Sesame-Session: $SESSION_ID:$SESSION_SECRET" \\
  -d '{"action":"doc:read","resource":"project:alpha"}'

# {"decision":"deny","reason_code":"deny_no_grant",...}`,

  Go: `// SESAME_BINARY and SESAME_DEPLOYMENT come from the environment.
client, err := sesame.Start(ctx, sesame.Options{})
if err != nil {
    log.Fatal(err)
}
defer client.Close()

decision, err := client.Decide(ctx, sesame.DecisionRequest{
    TenantID:    tenantID,
    PrincipalID: principalID,
    Action:      "doc:read",
    Resource:    "project:alpha",
}, nil)

fmt.Println(decision.Decision, decision.ReasonCode)
// deny deny_no_grant`,
}

export default class extends Tac {
  heading = 'Over HTTP, or from Go.'
  languages = ['HTTP', ...SDK_LANGUAGES]
  active = 'HTTP'

  get snippet() {
    return SNIPPETS[this.active] || ''
  }

  select(language) {
    this.active = language
  }
}
