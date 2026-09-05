# DriftGuard Test Files

A set of intentional Dockerfile + Kubernetes YAML pairs for testing every rule in the scanner.
Each subfolder is a named scenario. Load both files into DriftGuard to see the expected findings.

---

## Scenarios

| Folder / File | What it tests |
|---|---|
| `01-all-clean/` | Perfect files — should score 100/100, verdict PASS |
| `02-dockerfile-issues/` | All 5 Dockerfile standalone checks firing |
| `03-k8s-issues/` | All 8 K8s standalone checks firing |
| `04-drift-full/` | All 7 drift rules firing simultaneously |
| `05-partial-drift/` | Only DRIFT-01 and DRIFT-03 (minimal demo pair) |
| `06-real-world-node/` | Realistic Node.js microservice — mixed bag of real issues |
| `07-real-world-python/` | Realistic Python/FastAPI service — different issue set |
