// Runs the shared SDK contract scenario against real compiled binaries.
// The Go and Python suites drive the identical sequence, so a divergence in
// any single SDK fails its own suite rather than hiding behind a mock.

import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, mkdirSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { after, before, test } from 'node:test'

import { Client, ProtocolError } from './sesame.mjs'

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..')
let workspace
let sesameBinary
let fakeFYLO
let client

before(async () => {
    workspace = mkdtempSync(path.join(tmpdir(), 'sesame-node-contract-'))
    sesameBinary = path.join(workspace, 'sesame')
    fakeFYLO = path.join(workspace, 'fake-fylo')
    for (const [output, source] of [
        [sesameBinary, './cmd/sesame'],
        [fakeFYLO, './internal/adapters/fylo/testdata/fakefylo']
    ]) {
        execFileSync('go', ['build', '-trimpath', '-o', output, source], {
            cwd: repositoryRoot,
            env: { ...process.env, CGO_ENABLED: '0', GOTOOLCHAIN: 'auto' }
        })
    }
    const root = path.join(workspace, 'root')
    mkdirSync(root, { mode: 0o700 })
    client = await Client.start({ binary: sesameBinary, fyloBinary: fakeFYLO, fyloRoot: root })
})

after(async () => {
    if (client) await client.close()
    if (workspace) rmSync(workspace, { recursive: true, force: true })
})

test('system operations report a storage-backed process', async () => {
    assert.equal((await client.ping()).status, 'ok')
    assert.equal((await client.readiness()).status, 'ok')
    assert.equal((await client.version()).name, 'sesame')
    assert.equal((await client.metrics()).storage_configured, true)
})

test('administrator bootstrap converges', async () => {
    const first = await client.adminBootstrap('acme', { namespace: 'email', value: 'Admin@Example.com' })
    assert.equal(first.created, true)
    assert.equal(first.administrator.identifier.value, 'admin@example.com')
    assert.equal(first.role.name, 'administrator')

    const second = await client.adminBootstrap('acme', { namespace: 'email', value: 'admin@example.com' })
    assert.equal(second.created, false)
    assert.equal(second.tenant.tenant_id, first.tenant.tenant_id)
    assert.equal(second.grant.grant_id, first.grant.grant_id)

    const decision = await client.decide({
        tenant_id: first.tenant.tenant_id,
        principal_id: first.administrator.principal_id,
        action: 'tenant:configure',
        resource: 'deployment:root'
    })
    assert.equal(decision.decision, 'allow')
})

test('principals, identifiers, roles, grants, and decisions', async () => {
    const tenant = (await client.tenantGetByName('acme')).tenant_id

    const alice = await client.principalCreate(tenant, 'human', { namespace: 'email', value: 'Alice@Example.com' })
    assert.equal(alice.identifier.value, 'alice@example.com')
    assert.equal(alice.status, 'active')

    await assert.rejects(
        () => client.principalCreate(tenant, 'workload', { namespace: 'email', value: 'alice@example.com' }),
        (error) => error instanceof ProtocolError && error.code === 'identifier_conflict'
    )

    const resolved = await client.principalGetByIdentifier(tenant, { namespace: 'email', value: 'alice@example.com' })
    assert.equal(resolved.principal_id, alice.principal_id)

    const role = await client.roleCreate(tenant, 'reader', [{ action: 'doc:read', resource: 'project:*' }])
    const request = {
        tenant_id: tenant,
        principal_id: alice.principal_id,
        action: 'doc:read',
        resource: 'project:alpha'
    }

    const denied = await client.decide(request)
    assert.equal(denied.decision, 'deny')
    assert.equal(denied.reason_code, 'deny_no_grant')

    const grant = await client.grantCreate(tenant, alice.principal_id, role.role_id)
    const allowed = await client.decide(request)
    assert.equal(allowed.decision, 'allow')
    assert.equal(allowed.reason_code, 'allow_role_grant')

    await assert.rejects(
        () => client.decide(request, allowed.policy_version - 1),
        (error) => error instanceof ProtocolError && error.code === 'stale_policy_version'
    )
    const pinned = await client.decide(request, allowed.policy_version)
    assert.equal(pinned.decision, 'allow')

    const batch = await client.decideBatch([request, { ...request, action: 'doc:delete' }])
    assert.equal(batch.length, 2)
    assert.equal(batch[0].decision, 'allow')
    assert.equal(batch[1].decision, 'deny')
    assert.equal(batch[0].policy_version, batch[1].policy_version)

    await client.grantRevoke(grant.grant_id)
    assert.equal((await client.decide(request)).decision, 'deny')
})

test('group membership drives decisions and removal denies', async () => {
    const tenant = (await client.tenantGetByName('acme')).tenant_id
    const bob = await client.principalCreate(tenant, 'human', { namespace: 'email', value: 'bob@example.com' })
    const role = await client.roleCreate(tenant, 'group-reader', [{ action: 'doc:read', resource: '*' }])
    const group = await client.groupCreate(tenant, 'readers')
    await client.grantCreateForGroup(tenant, group.group_id, role.role_id)

    const request = {
        tenant_id: tenant,
        principal_id: bob.principal_id,
        action: 'doc:read',
        resource: 'file:a'
    }
    assert.equal((await client.decide(request)).decision, 'deny')

    await client.groupMemberAdd(group.group_id, bob.principal_id)
    const allowed = await client.decide(request)
    assert.equal(allowed.decision, 'allow')
    assert.equal(allowed.reason_code, 'allow_group_grant')

    await assert.rejects(
        () => client.groupMemberAdd(group.group_id, bob.principal_id),
        (error) => error instanceof ProtocolError && error.code === 'group_member_exists'
    )

    await client.groupMemberRemove(group.group_id, bob.principal_id)
    assert.equal((await client.decide(request)).decision, 'deny')
})

test('suspension denies and unknown records return stable codes', async () => {
    const tenant = (await client.tenantGetByName('acme')).tenant_id
    const carol = await client.principalCreate(tenant, 'workload', { namespace: 'login', value: 'carol' })
    const role = await client.roleCreate(tenant, 'suspendable', [{ action: 'job:run', resource: '*' }])
    await client.grantCreate(tenant, carol.principal_id, role.role_id)

    const request = {
        tenant_id: tenant,
        principal_id: carol.principal_id,
        action: 'job:run',
        resource: 'queue:default'
    }
    assert.equal((await client.decide(request)).decision, 'allow')

    const suspended = await client.principalSuspend(carol.principal_id)
    assert.equal(suspended.status, 'suspended')
    const afterSuspend = await client.decide(request)
    assert.equal(afterSuspend.decision, 'deny')
    assert.equal(afterSuspend.reason_code, 'deny_principal_suspended')

    await assert.rejects(
        () => client.tenantGetByName('missing'),
        (error) => error instanceof ProtocolError && error.code === 'tenant_not_found'
    )
    await assert.rejects(
        () => client.principalGetById('prn_00000000000000000000000000000000'),
        (error) => error instanceof ProtocolError && error.code === 'principal_not_found'
    )
    await assert.rejects(
        () => client.request('identity.unknown', {}),
        (error) => error instanceof ProtocolError && error.code === 'operation_not_found'
    )
})

// The shared golden decision corpus. The Go engine test and the Go and
// Python SDK suites build the identical fixture from the same JSON file, so
// no client can drift from the documented decision semantics.
test('shared golden decision corpus', async () => {
    const corpus = JSON.parse(
        readFileSync(path.join(repositoryRoot, 'api', 'machine', 'v1', 'decisions.golden.json'), 'utf8')
    )
    const setup = corpus.setup

    // The corpus needs a pristine deployment, so it gets its own root.
    const goldenRoot = path.join(workspace, 'golden-root')
    mkdirSync(goldenRoot, { mode: 0o700 })
    const client = await Client.start({ binary: sesameBinary, fyloBinary: fakeFYLO, fyloRoot: goldenRoot })
    try {

    const tenant = (await client.tenantBootstrap(setup.tenant)).tenant.tenant_id
    const other = (await client.tenantBootstrap(setup.other_tenant)).tenant.tenant_id

    const principals = {}
    for (const wanted of setup.principals) {
        const created = await client.principalCreate(tenant, wanted.kind, {
            namespace: wanted.namespace,
            value: wanted.value
        })
        principals[wanted.name] = created.principal_id
    }
    const roles = {}
    for (const wanted of setup.roles) {
        roles[wanted.name] = (await client.roleCreate(tenant, wanted.name, wanted.permissions)).role_id
    }
    const groups = {}
    for (const wanted of setup.groups) {
        const created = await client.groupCreate(tenant, wanted.name)
        groups[wanted.name] = created.group_id
        for (const member of wanted.members) {
            await client.groupMemberAdd(created.group_id, principals[member])
        }
    }
    for (const wanted of setup.grants) {
        if (wanted.group) await client.grantCreateForGroup(tenant, groups[wanted.group], roles[wanted.role])
        else await client.grantCreate(tenant, principals[wanted.principal], roles[wanted.role])
    }
    for (const name of setup.suspended) {
        await client.principalSuspend(principals[name])
    }

    for (const testCase of corpus.cases) {
        const request = {
            tenant_id: testCase.tenant_id ?? (testCase.tenant === 'other' ? other : tenant),
            principal_id: testCase.principal_id ?? principals[testCase.principal],
            action: testCase.action,
            resource: testCase.resource,
            ...(testCase.context ? { context: testCase.context } : {})
        }
        const decision = await client.decide(request)
        assert.equal(decision.decision, testCase.decision, testCase.name)
        assert.equal(decision.reason_code, testCase.reason_code, testCase.name)
        assert.equal(decision.missing_context_key ?? '', testCase.missing_context_key ?? '', testCase.name)
    }
    } finally {
        await client.close()
    }
})

// The full login flow. The Go and Python suites drive the identical
// sequence, so a divergence in any single SDK fails its own suite.
test('password authentication issues and revokes a usable session', async () => {
    const tenant = (await client.tenantGetByName('acme')).tenant_id
    const principal = await client.principalCreate(tenant, 'human', {
        namespace: 'email',
        value: 'login@example.com'
    })
    const password = 'correct horse battery staple'
    await client.setPassword(principal.principal_id, password)

    const begun = await client.authnBegin(tenant, { namespace: 'email', value: 'Login@Example.com' })
    assert.equal(begun.state, 'awaiting_factor')

    const wrong = await client.authnVerifyPassword(begun.transaction_id, 'wrong password value')
    assert.equal(wrong.attempts_left, 4)

    const verified = await client.authnVerifyPassword(begun.transaction_id, password)
    assert.equal(verified.assurance, 'password')

    const issued = await client.authnComplete(begun.transaction_id, 3600)
    assert.ok(issued.session_secret)

    const session = await client.sessionVerify(issued.session_id, issued.session_secret)
    assert.equal(session.principal_id, principal.principal_id)
    assert.equal(session.secret_digest, undefined)

    await assert.rejects(
        () => client.sessionVerify(issued.session_id, 'nope'),
        (error) => error instanceof ProtocolError && error.code === 'session_not_found'
    )

    await client.sessionRevoke(issued.session_id, 'test')
    await assert.rejects(
        () => client.sessionVerify(issued.session_id, issued.session_secret),
        (error) => error instanceof ProtocolError && error.code === 'session_inactive'
    )

    // An unknown identifier starts a transaction indistinguishable from a
    // known one: the engine must not confirm which identifiers exist.
    const unknown = await client.authnBegin(tenant, { namespace: 'email', value: 'ghost@example.com' })
    assert.equal(unknown.state, begun.state)
    const unknownAttempt = await client.authnVerifyPassword(unknown.transaction_id, password)
    assert.equal(unknownAttempt.attempts_left, 4)
    assert.equal(unknownAttempt.assurance, undefined)
})
