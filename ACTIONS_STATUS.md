# GitHub Actions Status

**Last Updated:** 2025-12-03

## Current Status: Offline (Temporarily)

GitHub Actions self-hosted runners are currently offline due to infrastructure changes.

## Infrastructure Changes

### Self-Hosted Runner Infrastructure

- **CKEL** - Local homelab infrastructure (Proxmox cluster with VFIO GPU passthrough)
- **CKTECH** - Production bare metal (Interserver NY region)

| Node | Specs | Role |
|------|-------|------|
| PVE1 (chromium) | 5950x, 128GB DDR4, 2x RTX 3090 | GPU compute |
| PVE2 (palladium) | 14900k, 128GB DDR5, RTX 4090 | GPU compute |
| PVE3 (osmium) | Ryzen 5800x, 64GB DDR4, RTX 3070 | GPU compute |
| PVE4 (CKTECH) | 7950x, 128GB DDR5 ECC, ZFS RAID-Z2 | GitLab CE (staged) |
| PVE5 (CKTECH-spare) | 5900x, 128GB ECC, ZFS | Veeam/Minio - Retiring Q1-Q2 2026 |
| PVE6 | i7-9900k, 64GB, RTX 2060 | nvcontrol testing (20-series) |
| PVE7 (prometheus) | 12900KF, 64GB, RTX 2060 | **Temporary Actions runner** (coming soon) | 

### GPU Shuffle (Proxmox VFIO)

We're reorganizing our GPU compute infrastructure across Proxmox hosts:

| Host | GPUs | Status |
|------|------|--------|
| PVE1 (chromium) | 2x RTX 3090 | Operational |
| PVE2 (palladium) | RTX 4090 | Operational |
| PVE3 (osmium) | RTX 3070 | Operational |
| PVE4 (CKTECH) | - | Staging (GitLab CE) |
| PVE5 (CKTECH-spare) | - | Retiring Q1-Q2 2026 |
| PVE6 | RTX 2060 | nvcontrol testing |
| PVE7 (prometheus) | RTX 2060 | **Actions runner (coming soon)** |
| Nvidia DGX Spark | GB10 Grace Blackwell | Agentic AI, prototyping, QA automation (CI/CD planned) |

### Migration Plan

We're transitioning from:
- **Current:** VM + Docker containers with NVIDIA Container Runtime
- **Target:** Bare metal production server (PVE4) with persistent GPU workloads

Additionally, we've staged **GitLab CE** as a potential CI/CD alternative.

## ETA

Actions should be back online shortly after the GPU shuffle is complete.

## Self-Hosted Runner Setup

See `ci-example/` for the Docker-based runner configuration used previously:
- `Dockerfile` - Ubuntu 24.04 with Zig nightly + NVIDIA toolkit
- `compose.yml` - Docker Compose with GPU passthrough
- `entrypoint.sh` - Runner registration script

## Local CI Alternative

While Actions are offline, use the local CI suite:

```bash
./dev/ci.sh          # Full CI (build, test, lint)
./dev/ci.sh --quick  # Quick mode (skip tests)
./dev/bench.sh       # Run benchmarks
```

## Contact

For CI/infrastructure questions, check the repo issues or reach out to maintainers.
