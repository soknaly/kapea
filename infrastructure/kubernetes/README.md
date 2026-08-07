# KAPEA Kubernetes manifests

Practical manifests for deploying KAPEA to Kubernetes. Replace `REGISTRY` image placeholders with your container registry.

## Prerequisites

- Kubernetes 1.28+
- Ingress controller (for public API access)
- PostgreSQL, Redis (BullMQ), MinIO/S3, and ClamAV (in-cluster or managed)
- `kapea-yara-rules` ConfigMap populated from `infrastructure/yara/rules/`

## Apply order

```bash
# 1. Namespace
kubectl apply -f infrastructure/kubernetes/namespace.yaml

# 2. Config and secrets (copy secret.example.yaml → secret.yaml first)
kubectl apply -f infrastructure/kubernetes/configmap.yaml
kubectl apply -f infrastructure/kubernetes/secret.yaml

# 3. YARA rules ConfigMap (example)
kubectl create configmap kapea-yara-rules \
  --from-file=infrastructure/yara/rules \
  -n kapea \
  --dry-run=client -o yaml | kubectl apply -f -

# 4. Seccomp profile (install on each node or via security profile CRD)
# Copy infrastructure/kubernetes/seccomp/scan-worker.json to each node's
# /var/lib/kubelet/seccomp/kapea-scan-worker.json

# 5. Deployments and services
kubectl apply -f infrastructure/kubernetes/deployment-api.yaml
kubectl apply -f infrastructure/kubernetes/deployment-result-consumer.yaml
kubectl apply -f infrastructure/kubernetes/deployment-retention-worker.yaml
kubectl apply -f infrastructure/kubernetes/deployment-rust-scan-worker.yaml

# 6. Autoscaling and network policies
kubectl apply -f infrastructure/kubernetes/hpa.yaml
kubectl apply -f infrastructure/kubernetes/networkpolicy.yaml
```

## BullMQ / Redis

Scan jobs use BullMQ on Redis (`REDIS_URL`). Queue name: `scan-jobs`. Job name: `scan.requested`. Progress and completion are BullMQ job lifecycle/progress/return values — no separate stream init job is required.

## Scaling notes

- **API HPA** scales on CPU (70% target). Tune `minReplicas`/`maxReplicas` for your traffic.
- **Scan worker HPA** scales on CPU. For queue-depth scaling, add KEDA or Prometheus Adapter with Redis/BullMQ waiting-job metrics.

## Security

- Scan workers run as non-root with a restrictive seccomp profile.
- Network policies deny public ingress to workers; workers may egress to ClamAV, Redis, and storage only.
- See [docs/security.md](../../docs/security.md) for AppArmor and seccomp details.

## Build and push images

```bash
docker build -f infrastructure/docker/Dockerfile.api -t REGISTRY/kapea-api:latest .
docker build -f infrastructure/docker/Dockerfile.result-consumer -t REGISTRY/kapea-result-consumer:latest .
docker build -f infrastructure/docker/Dockerfile.retention-worker -t REGISTRY/kapea-retention-worker:latest .
docker build -f infrastructure/docker/Dockerfile.scan-worker -t REGISTRY/kapea-scan-worker:latest .
```

Push to your registry and update deployment image fields.
