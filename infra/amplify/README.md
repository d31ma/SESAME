# SESAME Amplify hosting

`hosting.yaml` defines the production static-site hosting for
`website/dist/web`. It creates the Amplify app, the `production` branch, and
the managed TLS domain association for `sesame.del.ma`.

The domain is managed by Route 53 in the same AWS account, so Amplify manages
the validation and routing records during the domain-association workflow.

## Deploy the infrastructure

```bash
aws cloudformation deploy \
  --region ca-central-1 \
  --stack-name sesame-amplify-hosting \
  --template-file infra/amplify/hosting.yaml \
  --tags Environment=production Project=SESAME Owner=DELMA \
    CostCenter=DELMA ManagedBy=CloudFormation
```

## Deploy the website

Do not deploy the website by hand. Each release attaches
`sesame-site-<version>.zip` to its GitHub release, and the `Site Deploy`
workflow deploys it to the `production` branch after kestrel's Floci staging
check. To roll back or redeploy, dispatch `Site Deploy` with a released
version and target `production`. See `docs/RELEASE_ENGINEERING.md`
("Website").

This template stays the owner of the app (`dgt8kb065o3d1`), its `production`
branch, its rewrite rules and the `sesame.del.ma` domain (the owner's choice
on 2026-11-11). `d31ma/PaaS` owns only the deploy role
`sesame-site-deploy-production` and the Floci staging copy. When you change
the rewrite rules here, also update `infra/sesame/amplify/custom-rules.json`
in `d31ma/PaaS`, which staging mirrors. Never delete the stack
`sesame-amplify-hosting`: its resources have no `Retain` policy, so a delete
would delete the live site.
