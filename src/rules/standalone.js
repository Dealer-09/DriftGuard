/**
 * Standalone Rule Engine
 * Pure functions: (parsed) => Finding[]
 * Each Finding shape mirrors cli/models.py Finding (ported from Python).
 * CIS control IDs from CIS Kubernetes Benchmark v1.8 and CIS Docker Benchmark v1.6.
 */

import { CVE_CORRELATION } from '../lib/cveMap.js';

function makeFinding(overrides) {
  return {
    id: Math.random().toString(36).slice(2, 10),
    category: 'standalone',
    confidence: 'HIGH',
    cves: [],
    ...overrides,
  };
}

function withCVEs(finding, key) {
  const cves = CVE_CORRELATION[key] || [];
  return { ...finding, cves };
}

// ─── DOCKERFILE CHECKS ───────────────────────────────────────────────────────

const SECRET_PATTERN = /(?:key|token|password|secret|passwd|pwd|api_key|auth|credential|access_key|private_key)\s*[=:]\s*\S+/i;

export function checkDockerfile(parsed) {
  const findings = [];
  if (!parsed) return findings;

  // DF-01: No USER instruction (running as root)
  if (!parsed.finalStageUser) {
    findings.push(makeFinding({
      id_code: 'DF-01',
      severity: 'HIGH',
      title: 'No USER instruction — container runs as root',
      detail: 'Without a USER instruction the container process runs as root (UID 0). A container escape grants full host root access.',
      file: 'Dockerfile',
      cisControl: 'CIS-Docker-4.1',
      category: 'dockerfile',
    }));
  }

  // DF-02: Base image uses :latest or no tag
  if (parsed.baseImage) {
    const imageRef = parsed.baseImage;
    const hasDigest = imageRef.includes('@sha256:');
    const hasTag = imageRef.includes(':') && !imageRef.endsWith(':latest');
    if (!hasDigest && !hasTag) {
      findings.push(makeFinding({
        id_code: 'DF-02',
        severity: 'MEDIUM',
        title: 'Base image uses :latest or has no tag',
        detail: `"${imageRef}" is not pinned to a specific version or digest. Unpinned images can silently pull malicious updates.`,
        file: 'Dockerfile',
        cisControl: 'CIS-Docker-4.3',
        category: 'dockerfile',
      }));
    }
  }

  // DF-03: Hardcoded secrets in ENV / ARG
  for (const instr of [...parsed.envVars, ...parsed.argVars]) {
    if (SECRET_PATTERN.test(instr.args)) {
      findings.push(makeFinding({
        id_code: 'DF-03',
        severity: 'CRITICAL',
        title: `Potential hardcoded secret in ${instr.instruction}`,
        detail: `Line ${instr.line}: "${instr.raw}" — secret-like value detected. Baked into the image layer and visible in docker inspect.`,
        file: 'Dockerfile',
        line: instr.line,
        cisControl: 'CIS-Docker-4.9',
        category: 'dockerfile',
      }));
    }
  }

  // DF-04: ADD used where COPY would do
  for (const instr of parsed.addInstructions) {
    const args = instr.args;
    const isURL = /^https?:\/\//i.test(args);
    const isTar = /\.(tar|tar\.gz|tgz|tar\.bz2|tar\.xz)/.test(args);
    if (!isURL && !isTar) {
      findings.push(makeFinding({
        id_code: 'DF-04',
        severity: 'LOW',
        title: 'ADD used instead of COPY',
        detail: `Line ${instr.line}: COPY is preferred over ADD for local files. ADD has implicit behaviours (auto-extraction, URL fetching) that increase attack surface.`,
        file: 'Dockerfile',
        line: instr.line,
        cisControl: 'CIS-Docker-4.9',
        category: 'dockerfile',
      }));
    }
  }

  // DF-05: No HEALTHCHECK
  if (!parsed.hasHealthcheck) {
    findings.push(makeFinding({
      id_code: 'DF-05',
      severity: 'LOW',
      title: 'No HEALTHCHECK instruction',
      detail: 'Without HEALTHCHECK, container orchestrators cannot detect application failures and may route traffic to unhealthy instances.',
      file: 'Dockerfile',
      cisControl: 'CIS-Docker-4.6',
      category: 'dockerfile',
    }));
  }

  return findings;
}

// ─── KUBERNETES CHECKS ───────────────────────────────────────────────────────

export function checkK8sManifests(docs, extractContainers, getPodSecurityContext) {
  const findings = [];
  if (!docs || docs.length === 0) return findings;

  for (const doc of docs) {
    const kind = doc?.kind || 'Unknown';
    const name = doc?.metadata?.name || 'unnamed';
    const resourceLabel = `${kind}/${name}`;

    const containers = extractContainers(doc);
    const podSecCtx = getPodSecurityContext(doc);

    // K8S-01: privileged: true
    for (const { container } of containers) {
      if (container?.securityContext?.privileged === true) {
        findings.push(withCVEs(makeFinding({
          id_code: 'K8S-01',
          severity: 'CRITICAL',
          title: `Privileged container: ${container.name}`,
          detail: `${resourceLabel} runs container "${container.name}" in privileged mode — equivalent to root on the host node.`,
          file: 'k8s-manifest.yaml',
          cisControl: 'CIS-K8s-5.2.1',
          category: 'k8s',
        }), 'PRIVILEGED_CONTAINER'));
      }
    }

    // K8S-02: runAsUser: 0 or missing runAsNonRoot
    for (const { container, podSpec } of containers) {
      const sc = container?.securityContext || {};
      const podRunAsUser = podSecCtx?.runAsUser;
      const podRunAsNonRoot = podSecCtx?.runAsNonRoot;

      const runsAsRoot =
        sc.runAsUser === 0 ||
        podRunAsUser === 0 ||
        (sc.runAsNonRoot !== true && podRunAsNonRoot !== true && sc.runAsUser === undefined);

      if (runsAsRoot) {
        findings.push(withCVEs(makeFinding({
          id_code: 'K8S-02',
          severity: 'HIGH',
          title: `Container may run as root: ${container.name}`,
          detail: `${resourceLabel}/"${container.name}" has no runAsNonRoot:true and no non-zero runAsUser. Container process runs as UID 0.`,
          file: 'k8s-manifest.yaml',
          cisControl: 'CIS-K8s-5.2.6',
          category: 'k8s',
        }), 'RUN_AS_ROOT'));
      }
    }

    // K8S-03: Missing resource limits / requests
    for (const { container } of containers) {
      const res = container?.resources || {};
      if (!res.limits || !res.requests) {
        findings.push(makeFinding({
          id_code: 'K8S-03',
          severity: 'MEDIUM',
          title: `Missing resource limits/requests: ${container.name}`,
          detail: `${resourceLabel}/"${container.name}" has no CPU/memory limits. Enables resource exhaustion (DoS) attacks.`,
          file: 'k8s-manifest.yaml',
          cisControl: 'CIS-K8s-5.2.4',
          category: 'k8s',
        }));
      }
    }

    // K8S-04: Image uses :latest
    for (const { container } of containers) {
      const image = container?.image || '';
      const hasDigest = image.includes('@sha256:');
      const hasPin = image.includes(':') && !image.endsWith(':latest');
      if (!hasDigest && !hasPin) {
        findings.push(makeFinding({
          id_code: 'K8S-04',
          severity: 'MEDIUM',
          title: `Unpinned image tag: ${container.name}`,
          detail: `${resourceLabel}/"${container.name}" uses image "${image}" without a pinned tag or digest.`,
          file: 'k8s-manifest.yaml',
          cisControl: 'CIS-K8s-5.4.4',
          category: 'k8s',
        }));
      }
    }

    // K8S-05: Secrets as literal env values
    for (const { container } of containers) {
      for (const envEntry of container?.env || []) {
        if (envEntry.value !== undefined && !envEntry.valueFrom) {
          if (SECRET_PATTERN.test(envEntry.name)) {
            findings.push(withCVEs(makeFinding({
              id_code: 'K8S-05',
              severity: 'HIGH',
              title: `Literal secret in env: ${envEntry.name}`,
              detail: `${resourceLabel}/"${container.name}" passes "${envEntry.name}" as a plain env value. Use valueFrom.secretKeyRef instead.`,
              file: 'k8s-manifest.yaml',
              cisControl: 'CIS-K8s-5.4.1',
              category: 'k8s',
            }), 'LITERAL_SECRET_ENV'));
          }
        }
      }
    }

    // K8S-06: hostNetwork / hostPID / hostIPC
    const podSpec = doc?.spec?.template?.spec || doc?.spec || {};
    if (podSpec.hostNetwork === true) {
      findings.push(withCVEs(makeFinding({
        id_code: 'K8S-06a',
        severity: 'HIGH',
        title: `hostNetwork: true in ${resourceLabel}`,
        detail: 'Pod shares the host network namespace — bypasses all NetworkPolicy and Kubernetes network isolation.',
        file: 'k8s-manifest.yaml',
        cisControl: 'CIS-K8s-5.2.4',
        category: 'k8s',
      }), 'HOST_NETWORK'));
    }
    if (podSpec.hostPID === true) {
      findings.push(makeFinding({
        id_code: 'K8S-06b',
        severity: 'HIGH',
        title: `hostPID: true in ${resourceLabel}`,
        detail: 'Pod can see all host processes — trivially enables ptrace-based container escapes.',
        file: 'k8s-manifest.yaml',
        cisControl: 'CIS-K8s-5.2.2',
        category: 'k8s',
      }));
    }
    if (podSpec.hostIPC === true) {
      findings.push(makeFinding({
        id_code: 'K8S-06c',
        severity: 'HIGH',
        title: `hostIPC: true in ${resourceLabel}`,
        detail: 'Pod shares host IPC namespace — enables shared memory attacks against host processes.',
        file: 'k8s-manifest.yaml',
        cisControl: 'CIS-K8s-5.2.3',
        category: 'k8s',
      }));
    }

    // K8S-07: allowPrivilegeEscalation not explicitly false
    for (const { container } of containers) {
      const ape = container?.securityContext?.allowPrivilegeEscalation;
      if (ape !== false) {
        findings.push(withCVEs(makeFinding({
          id_code: 'K8S-07',
          severity: 'HIGH',
          title: `allowPrivilegeEscalation not false: ${container.name}`,
          detail: `${resourceLabel}/"${container.name}" does not set allowPrivilegeEscalation:false — enables setuid/sudo privilege escalation.`,
          file: 'k8s-manifest.yaml',
          cisControl: 'CIS-K8s-5.2.5',
          category: 'k8s',
        }), 'ALLOW_PRIVILEGE_ESCALATION'));
      }
    }

    // K8S-08: Missing readOnlyRootFilesystem
    for (const { container } of containers) {
      const rorf = container?.securityContext?.readOnlyRootFilesystem;
      if (rorf !== true) {
        findings.push(withCVEs(makeFinding({
          id_code: 'K8S-08',
          severity: 'MEDIUM',
          title: `No readOnlyRootFilesystem: ${container.name}`,
          detail: `${resourceLabel}/"${container.name}" has a writable root filesystem — attackers can modify binaries or write malware.`,
          file: 'k8s-manifest.yaml',
          cisControl: 'CIS-K8s-5.2.6',
          category: 'k8s',
        }), 'MISSING_READ_ONLY_ROOT'));
      }
    }
  }

  return findings;
}
