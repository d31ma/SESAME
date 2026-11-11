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

`d31ma/PaaS` is taking over this app (`dgt8kb065o3d1`), its headers, rewrite
rules and domain. Once PaaS owns it, this template and this folder are removed.
