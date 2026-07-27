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

## Package and deploy the website

The zip must contain `index.html` at its root, not a parent `web` directory:

```bash
app_id="$(aws cloudformation describe-stacks \
  --region ca-central-1 \
  --stack-name sesame-amplify-hosting \
  --query 'Stacks[0].Outputs[?OutputKey==`AppId`].OutputValue' \
  --output text)"
(
  cd website/dist/web
  find . -type f -print | LC_ALL=C sort |
    zip -X ../../../website/dist/sesame-web.zip -@
)
```

Create the Amplify upload slot, upload without logging the signed URL, and
start the deployment:

```bash
deployment="$(aws amplify create-deployment \
  --region ca-central-1 \
  --app-id "$app_id" \
  --branch-name production)"
job_id="$(jq -r .jobId <<<"$deployment")"
upload_url="$(jq -r .zipUploadUrl <<<"$deployment")"
curl --fail --silent --show-error \
  -H 'Content-Type: application/zip' \
  --upload-file website/dist/sesame-web.zip \
  "$upload_url"
unset upload_url deployment
aws amplify start-deployment \
  --region ca-central-1 \
  --app-id "$app_id" \
  --branch-name production \
  --job-id "$job_id"
```
