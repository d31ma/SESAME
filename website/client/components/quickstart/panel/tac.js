import { SDK_LANGUAGES } from '../../../shared/scripts/facts.js'

// One snippet per language, each doing the same thing: start the engine, ask
// whether a principal may perform an action, and read the reason back.
//
// These are written against the real shim signatures in clients/, not against
// an idealised API — a snippet on a homepage that does not compile is worse
// than no snippet. `deny_no_grant` is what an ungranted principal actually
// gets back, so the example shows a denial rather than a flattering allow.
//
// None of them names a deployment. Every shim omits the flag when the option
// is absent, so the engine resolves SESAME_DEPLOYMENT out of the environment
// it inherits — which is the whole point of the variable, and the reason the
// same program moves between a laptop, a container, and CI unchanged.
const SNIPPETS = {
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

  'Node.js': `import { Client } from './sesame.mjs'

// SESAME_BINARY and SESAME_DEPLOYMENT come from the environment.
const client = await Client.start()

const decision = await client.decide({
    tenant_id: tenantId,
    principal_id: principalId,
    action: 'doc:read',
    resource: 'project:alpha'
})

console.log(decision.decision, decision.reason_code)
// deny deny_no_grant

await client.close()`,

  Python: `from sesame import Client

# SESAME_BINARY and SESAME_DEPLOYMENT come from the environment.
with Client() as client:
    decision = client.decide({
        "tenant_id": tenant_id,
        "principal_id": principal_id,
        "action": "doc:read",
        "resource": "project:alpha",
    })

    print(decision["decision"], decision["reason_code"])
    # deny deny_no_grant`,

  Rust: `// SESAME_BINARY and SESAME_DEPLOYMENT come from the environment.
let mut client = Client::start(Options::default())?;

let decision = client.decide(&tenant_id, &principal_id, "doc:read", "project:alpha")?;

println!("{} {}", decision["decision"], decision["reason_code"]);
// "deny" "deny_no_grant"`,

  Java: `// SESAME_BINARY and SESAME_DEPLOYMENT come from the environment.
try (Sesame client = new Sesame(new Sesame.Options())) {
    Object decision = client.decide(tenantId, principalId, "doc:read", "project:alpha");

    System.out.println(decision);
    // {decision=deny, reason_code=deny_no_grant, ...}
}`,

  Kotlin: `// SESAME_BINARY and SESAME_DEPLOYMENT come from the environment.
Client(Options()).use { client ->
    val decision = client.decide(tenantId, principalId, "doc:read", "project:alpha")

    println(decision)
    // {decision=deny, reason_code=deny_no_grant, ...}
}`,

  'C#': `// SESAME_BINARY and SESAME_DEPLOYMENT come from the environment.
using var client = new Client(new Options());

var decision = client.Decide(tenantId, principalId, "doc:read", "project:alpha");

Console.WriteLine(decision.GetProperty("reason_code"));
// deny_no_grant`,

  PHP: `use Sesame\\Client;

// SESAME_BINARY and SESAME_DEPLOYMENT come from the environment.
$client = new Client();

$decision = $client->decide($tenantId, $principalId, 'doc:read', 'project:alpha');

echo $decision['decision'], ' ', $decision['reason_code'], PHP_EOL;
// deny deny_no_grant

$client->close();`,

  Ruby: `# SESAME_BINARY and SESAME_DEPLOYMENT come from the environment.
client = Sesame::Client.new

decision = client.decide(tenant_id, principal_id, 'doc:read', 'project:alpha')

puts "#{decision['decision']} #{decision['reason_code']}"
# deny deny_no_grant

client.close`,

  Dart: `// SESAME_BINARY and SESAME_DEPLOYMENT come from the environment.
final client = await Client.start();

final decision =
    await client.decide(tenantId, principalId, 'doc:read', 'project:alpha');

print('\${decision['decision']} \${decision['reason_code']}');
// deny deny_no_grant

await client.close();`,
}

export default class extends Tac {
  heading = 'Ten languages, one engine.'
  languages = SDK_LANGUAGES
  active = SDK_LANGUAGES[0]

  get snippet() {
    return SNIPPETS[this.active] || ''
  }

  select(language) {
    this.active = language
  }
}
