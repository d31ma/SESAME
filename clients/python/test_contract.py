"""Runs the shared SDK contract scenario against real compiled binaries.

The Go and Node suites drive the identical sequence, so a divergence in any
single SDK fails its own suite rather than hiding behind a mock.
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

from sesame import Client, ProtocolError

REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parents[2]


class ContractTest(unittest.TestCase):
    workspace: str
    client: Client

    @classmethod
    def setUpClass(cls) -> None:
        cls.workspace = tempfile.mkdtemp(prefix="sesame-python-contract-")
        binaries = {
            "sesame": "./cmd/sesame",
            "fake-fylo": "./internal/adapters/fylo/testdata/fakefylo",
        }
        built = {}
        environment = {**os.environ, "CGO_ENABLED": "0", "GOTOOLCHAIN": "auto"}
        for name, source in binaries.items():
            output = os.path.join(cls.workspace, name)
            subprocess.run(  # noqa: S603 - fixed arguments
                ["go", "build", "-trimpath", "-o", output, source],
                cwd=REPOSITORY_ROOT,
                env=environment,
                check=True,
            )
            built[name] = output

        root = os.path.join(cls.workspace, "root")
        os.mkdir(root, mode=0o700)
        cls.client = Client(
            built["sesame"], fylo_binary=built["fake-fylo"], fylo_root=root
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.client.close()
        shutil.rmtree(cls.workspace, ignore_errors=True)

    def test_01_system_operations(self) -> None:
        self.assertEqual(self.client.ping()["status"], "ok")
        self.assertEqual(self.client.readiness()["status"], "ok")
        self.assertEqual(self.client.version()["name"], "sesame")
        self.assertTrue(self.client.metrics()["storage_configured"])

    def test_02_admin_bootstrap_converges(self) -> None:
        first = self.client.admin_bootstrap("acme", "email", "Admin@Example.com")
        self.assertTrue(first["created"])
        self.assertEqual(first["administrator"]["identifier"]["value"], "admin@example.com")
        self.assertEqual(first["role"]["name"], "administrator")

        second = self.client.admin_bootstrap("acme", "email", "admin@example.com")
        self.assertFalse(second["created"])
        self.assertEqual(second["tenant"]["tenant_id"], first["tenant"]["tenant_id"])
        self.assertEqual(second["grant"]["grant_id"], first["grant"]["grant_id"])

        decision = self.client.decide(
            {
                "tenant_id": first["tenant"]["tenant_id"],
                "principal_id": first["administrator"]["principal_id"],
                "action": "tenant:configure",
                "resource": "deployment:root",
            }
        )
        self.assertEqual(decision["decision"], "allow")

    def test_03_principals_roles_grants_decisions(self) -> None:
        tenant = self.client.tenant_get_by_name("acme")["tenant_id"]

        alice = self.client.principal_create(tenant, "human", "email", "Alice@Example.com")
        self.assertEqual(alice["identifier"]["value"], "alice@example.com")
        self.assertEqual(alice["status"], "active")

        with self.assertRaises(ProtocolError) as conflict:
            self.client.principal_create(tenant, "workload", "email", "alice@example.com")
        self.assertEqual(conflict.exception.code, "identifier_conflict")

        resolved = self.client.principal_get_by_identifier(tenant, "email", "alice@example.com")
        self.assertEqual(resolved["principal_id"], alice["principal_id"])

        role = self.client.role_create(
            tenant, "reader", [{"action": "doc:read", "resource": "project:*"}]
        )
        request = {
            "tenant_id": tenant,
            "principal_id": alice["principal_id"],
            "action": "doc:read",
            "resource": "project:alpha",
        }

        denied = self.client.decide(request)
        self.assertEqual(denied["decision"], "deny")
        self.assertEqual(denied["reason_code"], "deny_no_grant")

        grant = self.client.grant_create(tenant, alice["principal_id"], role["role_id"])
        allowed = self.client.decide(request)
        self.assertEqual(allowed["decision"], "allow")
        self.assertEqual(allowed["reason_code"], "allow_role_grant")

        with self.assertRaises(ProtocolError) as stale:
            self.client.decide(request, allowed["policy_version"] - 1)
        self.assertEqual(stale.exception.code, "stale_policy_version")
        pinned = self.client.decide(request, allowed["policy_version"])
        self.assertEqual(pinned["decision"], "allow")

        batch = self.client.decide_batch([request, {**request, "action": "doc:delete"}])
        self.assertEqual(len(batch), 2)
        self.assertEqual(batch[0]["decision"], "allow")
        self.assertEqual(batch[1]["decision"], "deny")
        self.assertEqual(batch[0]["policy_version"], batch[1]["policy_version"])

        self.client.grant_revoke(grant["grant_id"])
        self.assertEqual(self.client.decide(request)["decision"], "deny")

    def test_04_group_membership(self) -> None:
        tenant = self.client.tenant_get_by_name("acme")["tenant_id"]
        bob = self.client.principal_create(tenant, "human", "email", "bob@example.com")
        role = self.client.role_create(
            tenant, "group-reader", [{"action": "doc:read", "resource": "*"}]
        )
        group = self.client.group_create(tenant, "readers")
        self.client.grant_create_for_group(tenant, group["group_id"], role["role_id"])

        request = {
            "tenant_id": tenant,
            "principal_id": bob["principal_id"],
            "action": "doc:read",
            "resource": "file:a",
        }
        self.assertEqual(self.client.decide(request)["decision"], "deny")

        self.client.group_member_add(group["group_id"], bob["principal_id"])
        allowed = self.client.decide(request)
        self.assertEqual(allowed["decision"], "allow")
        self.assertEqual(allowed["reason_code"], "allow_group_grant")

        with self.assertRaises(ProtocolError) as duplicate:
            self.client.group_member_add(group["group_id"], bob["principal_id"])
        self.assertEqual(duplicate.exception.code, "group_member_exists")

        self.client.group_member_remove(group["group_id"], bob["principal_id"])
        self.assertEqual(self.client.decide(request)["decision"], "deny")

    def test_05_suspension_and_stable_errors(self) -> None:
        tenant = self.client.tenant_get_by_name("acme")["tenant_id"]
        carol = self.client.principal_create(tenant, "workload", "login", "carol")
        role = self.client.role_create(
            tenant, "suspendable", [{"action": "job:run", "resource": "*"}]
        )
        self.client.grant_create(tenant, carol["principal_id"], role["role_id"])

        request = {
            "tenant_id": tenant,
            "principal_id": carol["principal_id"],
            "action": "job:run",
            "resource": "queue:default",
        }
        self.assertEqual(self.client.decide(request)["decision"], "allow")

        suspended = self.client.principal_suspend(carol["principal_id"])
        self.assertEqual(suspended["status"], "suspended")
        after_suspend = self.client.decide(request)
        self.assertEqual(after_suspend["decision"], "deny")
        self.assertEqual(after_suspend["reason_code"], "deny_principal_suspended")

        for call, expected in (
            (lambda: self.client.tenant_get_by_name("missing"), "tenant_not_found"),
            (
                lambda: self.client.principal_get_by_id("prn_" + "0" * 32),
                "principal_not_found",
            ),
            (lambda: self.client.request("identity.unknown", {}), "operation_not_found"),
        ):
            with self.assertRaises(ProtocolError) as error:
                call()
            self.assertEqual(error.exception.code, expected)


if __name__ == "__main__":
    unittest.main()

    def test_06_password_authentication(self) -> None:
        tenant = self.client.tenant_get_by_name("acme")["tenant_id"]
        principal = self.client.principal_create(tenant, "human", "email", "login@example.com")
        password = "correct horse battery staple"
        self.client.set_password(principal["principal_id"], password)

        begun = self.client.authn_begin(tenant, "email", "Login@Example.com")
        self.assertEqual(begun["state"], "awaiting_factor")

        wrong = self.client.authn_verify_password(begun["transaction_id"], "wrong password value")
        self.assertEqual(wrong["attempts_left"], 4)

        verified = self.client.authn_verify_password(begun["transaction_id"], password)
        self.assertEqual(verified["assurance"], "password")

        issued = self.client.authn_complete(begun["transaction_id"], 3600)
        self.assertTrue(issued["session_secret"])

        session = self.client.session_verify(issued["session_id"], issued["session_secret"])
        self.assertEqual(session["principal_id"], principal["principal_id"])
        self.assertNotIn("secret_digest", session)

        with self.assertRaises(ProtocolError) as wrong_secret:
            self.client.session_verify(issued["session_id"], "nope")
        self.assertEqual(wrong_secret.exception.code, "session_not_found")

        self.client.session_revoke(issued["session_id"], "test")
        with self.assertRaises(ProtocolError) as revoked:
            self.client.session_verify(issued["session_id"], issued["session_secret"])
        self.assertEqual(revoked.exception.code, "session_inactive")

        # An unknown identifier is indistinguishable from a known one.
        unknown = self.client.authn_begin(tenant, "email", "ghost@example.com")
        self.assertEqual(unknown["state"], begun["state"])
        attempt = self.client.authn_verify_password(unknown["transaction_id"], password)
        self.assertEqual(attempt["attempts_left"], 4)
        self.assertNotIn("assurance", attempt)

class GoldenCorpusTest(unittest.TestCase):
    """The shared golden decision corpus.

    The Go engine test and the Go and Node SDK suites build the identical
    fixture from the same JSON file, so no client can drift from the
    documented decision semantics.
    """

    workspace: str
    client: Client

    @classmethod
    def setUpClass(cls) -> None:
        cls.workspace = tempfile.mkdtemp(prefix="sesame-python-golden-")
        environment = {**os.environ, "CGO_ENABLED": "0", "GOTOOLCHAIN": "auto"}
        built = {}
        for name, source in (
            ("sesame", "./cmd/sesame"),
            ("fake-fylo", "./internal/adapters/fylo/testdata/fakefylo"),
        ):
            output = os.path.join(cls.workspace, name)
            subprocess.run(  # noqa: S603 - fixed arguments
                ["go", "build", "-trimpath", "-o", output, source],
                cwd=REPOSITORY_ROOT,
                env=environment,
                check=True,
            )
            built[name] = output
        root = os.path.join(cls.workspace, "root")
        os.mkdir(root, mode=0o700)
        cls.client = Client(built["sesame"], fylo_binary=built["fake-fylo"], fylo_root=root)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.client.close()
        shutil.rmtree(cls.workspace, ignore_errors=True)

    def test_golden_corpus(self) -> None:
        corpus_path = REPOSITORY_ROOT / "api" / "machine" / "v1" / "decisions.golden.json"
        corpus = json.loads(corpus_path.read_text(encoding="utf-8"))
        setup = corpus["setup"]

        tenant = self.client.tenant_bootstrap(setup["tenant"])["tenant"]["tenant_id"]
        other = self.client.tenant_bootstrap(setup["other_tenant"])["tenant"]["tenant_id"]

        principals = {}
        for wanted in setup["principals"]:
            created = self.client.principal_create(
                tenant, wanted["kind"], wanted["namespace"], wanted["value"]
            )
            principals[wanted["name"]] = created["principal_id"]
        roles = {}
        for wanted in setup["roles"]:
            roles[wanted["name"]] = self.client.role_create(
                tenant, wanted["name"], wanted["permissions"]
            )["role_id"]
        groups = {}
        for wanted in setup["groups"]:
            created = self.client.group_create(tenant, wanted["name"])
            groups[wanted["name"]] = created["group_id"]
            for member in wanted["members"]:
                self.client.group_member_add(created["group_id"], principals[member])
        for wanted in setup["grants"]:
            if wanted.get("group"):
                self.client.grant_create_for_group(
                    tenant, groups[wanted["group"]], roles[wanted["role"]]
                )
            else:
                self.client.grant_create(
                    tenant, principals[wanted["principal"]], roles[wanted["role"]]
                )
        for name in setup["suspended"]:
            self.client.principal_suspend(principals[name])

        for case in corpus["cases"]:
            with self.subTest(case["name"]):
                request = {
                    "tenant_id": case.get("tenant_id")
                    or (other if case.get("tenant") == "other" else tenant),
                    "principal_id": case.get("principal_id")
                    or principals[case["principal"]],
                    "action": case["action"],
                    "resource": case["resource"],
                }
                if case.get("context"):
                    request["context"] = case["context"]
                decision = self.client.decide(request)
                self.assertEqual(decision["decision"], case["decision"])
                self.assertEqual(decision["reason_code"], case["reason_code"])
                self.assertEqual(
                    decision.get("missing_context_key", ""),
                    case.get("missing_context_key", ""),
                )
