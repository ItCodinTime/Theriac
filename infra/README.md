# Vultr-native deployment

PANACEA's production path is intentionally Vultr-only. The Kubernetes manifests
expect the following managed resources to exist before deployment:

1. A Vultr VPC with a managed NAT Gateway and a VPC-only VKE 1.36 cluster.
2. A Vultr Container Registry containing `backend` and `frontend` images.
3. Vultr Serverless Inference, a manual Vector Store collection, and a CVE collection.
4. Vultr Object Storage buckets named `panacea-manuals` and `panacea-evidence`.
   Enable Object Lock when the evidence bucket is created.
5. Vultr Managed Kafka with Schema Registry. Register the JSON schemas under
   `backend/schemas/events/` for Contract A and Contract B topics.
6. A Vultr IAM service user scoped to the required inference, VPC, NAT Gateway,
   Object Storage, and database resources. Configure OIDC and an assumable
   `panacea-operator` role for human overrides.

Copy `infra/k8s/secret.example.yaml` outside the repository, fill it from the
managed-service connection details, and create the secret. Never commit it.

```sh
kubectl apply -f infra/k8s/namespace.yaml
kubectl apply -f /secure/path/panacea-secrets.yaml
kubectl apply -k infra/k8s
```

Build and push both images to the Vultr Container Registry before applying the
manifests. Build the frontend with the public Vultr Load Balancer REST and WSS
addresses because `NEXT_PUBLIC_*` values are embedded during `next build`.

`VULTR_NATIVE_STRICT=true` is the production boundary: missing Object Storage,
Kafka, or OIDC configuration causes requests to fail instead of falling back to
local infrastructure.

Seed the Vultr-only CVE memory and register schemas with:

```sh
PYTHONPATH=backend python backend/scripts/ingest_cve.py /secure/path/cves.json
PYTHONPATH=backend python backend/scripts/register_kafka_schemas.py
```
