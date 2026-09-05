/**
 * Drift Engine — the core differentiator of DriftGuard.
 * Cross-checks Dockerfile against K8s manifests to detect where
 * the K8s layer silently undoes Dockerfile security hardening.
 *
 * Each drift rule takes both parsed artifacts and returns a Finding
 * with category: 'drift' and a narrative field explaining the intent reversal.
 */

function makeDrift(overrides) {
  return {
    id: Math.random().toString(36).slice(2, 10),
    category: 'drift',
    confidence: 'HIGH',
    cves: [],
    ...overrides,
  };
}

/**
 * Run all drift rules.
 * @param {object} parsedDockerfile - from dockerfileParser
 * @param {Array}  k8sDocs          - array of parsed YAML docs
 * @param {Function} extractContainers
 * @param {Function} getPodSecurityContext
 * @returns {Finding[]}
 */
export function checkDrift(parsedDockerfile, k8sDocs, extractContainers, getPodSecurityContext) {
  const findings = [];
  if (!parsedDockerfile || !k8sDocs || k8sDocs.length === 0) return findings;

  for (const doc of k8sDocs) {
    const kind = doc?.kind || 'Unknown';
    const name = doc?.metadata?.name || 'unnamed';
    const label = `${kind}/${name}`;
    const containers = extractContainers(doc);
    const podSpec = doc?.spec?.template?.spec || doc?.spec || {};
    const podSecCtx = getPodSecurityContext(doc);

    for (const { container } of containers) {
      const sc = container?.securityContext || {};

      // ─── DRIFT-01: User Override ───────────────────────────────────────────
      // Dockerfile sets a non-root USER → K8s runs the container as root anyway
      if (parsedDockerfile.finalStageUser) {
        const dfUser = parsedDockerfile.finalStageUser.args.trim();
        const isNonRootUser = dfUser !== '0' && dfUser !== 'root';

        if (isNonRootUser) {
          const k8sRunsAsRoot =
            sc.runAsUser === 0 ||
            podSecCtx.runAsUser === 0 ||
            (sc.runAsNonRoot !== true && podSecCtx.runAsNonRoot !== true && sc.runAsUser === undefined);

          if (k8sRunsAsRoot) {
            findings.push(makeDrift({
              id_code: 'DRIFT-01',
              severity: 'CRITICAL',
              title: `User override: Dockerfile hardens to "${dfUser}", K8s runs as root`,
              detail: `Your Dockerfile sets USER ${dfUser} (non-root). The K8s deployment for ${label}/"${container.name}" omits runAsNonRoot:true and runAsUser, silently reverting to root. All Dockerfile USER hardening is void.`,
              narrative: `Dockerfile intent: run as non-root user "${dfUser}". K8s reality: container runs as UID 0 (root).`,
              file: 'Dockerfile ↔ k8s-manifest.yaml',
              cisControl: 'CIS-K8s-5.2.6 / CIS-Docker-4.1',
              dockerfileLine: parsedDockerfile.finalStageUser.line,
            }));
          }
        }
      }

      // ─── DRIFT-02: Network Bypass ──────────────────────────────────────────
      // Dockerfile EXPOSE <port> → K8s hostNetwork:true makes port isolation meaningless
      if (parsedDockerfile.exposedPorts.length > 0 && podSpec.hostNetwork === true) {
        findings.push(makeDrift({
          id_code: 'DRIFT-02',
          severity: 'HIGH',
          title: `Network bypass: Dockerfile EXPOSEs ports, K8s uses hostNetwork:true`,
          detail: `Dockerfile exposes ports ${parsedDockerfile.exposedPorts.join(', ')} for controlled access. But ${label} sets hostNetwork:true — the container shares the host network namespace, rendering port-level isolation meaningless.`,
          narrative: 'Dockerfile intent: isolate network via explicit EXPOSE. K8s reality: hostNetwork bypasses all port-level isolation.',
          file: 'Dockerfile ↔ k8s-manifest.yaml',
          cisControl: 'CIS-K8s-5.2.4 / CIS-Docker-4.5',
        }));
      }

      // ─── DRIFT-03: Image Identity Drift ───────────────────────────────────
      // Dockerfile FROM is pinned → K8s image uses :latest or different tag
      if (parsedDockerfile.baseImage) {
        const dfImage = parsedDockerfile.baseImage;
        const dfIsPinned = dfImage.includes('@sha256:') ||
          (dfImage.includes(':') && !dfImage.endsWith(':latest'));

        const k8sImage = container?.image || '';
        const k8sIsPinned = k8sImage.includes('@sha256:') ||
          (k8sImage.includes(':') && !k8sImage.endsWith(':latest'));

        if (dfIsPinned && !k8sIsPinned) {
          findings.push(makeDrift({
            id_code: 'DRIFT-03',
            severity: 'HIGH',
            title: `Image drift: Dockerfile pins image, K8s deploys unpinned "${k8sImage}"`,
            detail: `Dockerfile builds from a pinned image "${dfImage}", but ${label}/"${container.name}" deploys "${k8sImage}" — an unpinned reference. The image you tested is not provably the image that ships.`,
            narrative: `Dockerfile intent: use a known, tested image build. K8s reality: deploys an unpinned image that may change between pulls.`,
            file: 'Dockerfile ↔ k8s-manifest.yaml',
            cisControl: 'CIS-K8s-5.4.4 / CIS-Docker-4.3',
            dockerfileLine: parsedDockerfile.fromInstructions[parsedDockerfile.fromInstructions.length - 1]?.line,
          }));
        }
      }

      // ─── DRIFT-04: Availability Hardening Dropped ─────────────────────────
      // Dockerfile has HEALTHCHECK → K8s missing both liveness + readiness probe
      if (parsedDockerfile.hasHealthcheck) {
        const hasLiveness = !!container?.livenessProbe;
        const hasReadiness = !!container?.readinessProbe;

        if (!hasLiveness && !hasReadiness) {
          findings.push(makeDrift({
            id_code: 'DRIFT-04',
            severity: 'MEDIUM',
            title: `Availability hardening dropped: Dockerfile HEALTHCHECK, K8s has no probes`,
            detail: `Dockerfile defines a HEALTHCHECK for "${container.name}", but ${label} has neither a livenessProbe nor a readinessProbe. Kubernetes will not restart unhealthy containers and may route traffic to dead replicas.`,
            narrative: 'Dockerfile intent: detect and recover from unhealthy states. K8s reality: no probes — orchestrator is blind to failures.',
            file: 'Dockerfile ↔ k8s-manifest.yaml',
            cisControl: 'CIS-Docker-4.6',
            dockerfileLine: parsedDockerfile.instructions.find(i => i.instruction === 'HEALTHCHECK')?.line,
          }));
        }
      }

      // ─── DRIFT-05: Capability Creep ───────────────────────────────────────
      // Dockerfile final stage is minimal/distroless → K8s adds capabilities or privileged
      if (parsedDockerfile.isDistroless) {
        const capsAdd = sc?.capabilities?.add || [];
        const isPrivileged = sc?.privileged === true;

        if (capsAdd.length > 0 || isPrivileged) {
          findings.push(makeDrift({
            id_code: 'DRIFT-05',
            severity: 'CRITICAL',
            title: `Capability creep: Distroless Dockerfile, K8s adds capabilities/privileged`,
            detail: `Dockerfile uses a minimal/distroless base image to reduce attack surface. But ${label}/"${container.name}" ${isPrivileged ? 'runs privileged' : `adds capabilities: [${capsAdd.join(', ')}]`} — negating the entire benefit of a minimal image.`,
            narrative: 'Dockerfile intent: minimal attack surface via distroless image. K8s reality: adds dangerous capabilities back.',
            file: 'Dockerfile ↔ k8s-manifest.yaml',
            cisControl: 'CIS-K8s-5.2.8 / CIS-Docker-4.1',
          }));
        }
      }

      // ─── DRIFT-06: Secret Hygiene Undone ──────────────────────────────────
      // Dockerfile has no hardcoded secrets → K8s manifest has literal secret env values
      const dfHasNoSecrets = !parsedDockerfile.envVars.some(e =>
        /(?:key|token|password|secret|passwd|pwd|api_key|auth|credential)\s*[=:]\s*\S+/i.test(e.args)
      );

      if (dfHasNoSecrets) {
        const literalSecrets = (container?.env || []).filter(e =>
          e.value !== undefined &&
          !e.valueFrom &&
          /(?:key|token|password|secret|passwd|pwd|api_key|auth|credential)/i.test(e.name)
        );
        if (literalSecrets.length > 0) {
          findings.push(makeDrift({
            id_code: 'DRIFT-06',
            severity: 'HIGH',
            title: `Secret hygiene undone: Dockerfile is clean, K8s injects literal secrets`,
            detail: `Dockerfile keeps no hardcoded secrets, but ${label}/"${container.name}" passes literal secret values via env: [${literalSecrets.map(s => s.name).join(', ')}]. Use valueFrom.secretKeyRef instead.`,
            narrative: 'Dockerfile intent: no secrets in image. K8s reality: secrets baked into pod spec in plain text.',
            file: 'Dockerfile ↔ k8s-manifest.yaml',
            cisControl: 'CIS-K8s-5.4.1 / CIS-Docker-4.9',
          }));
        }
      }

      // ─── DRIFT-07: Filesystem Hardening Dropped ───────────────────────────
      // Dockerfile uses distroless/scratch (implies read-only intent) → K8s missing readOnlyRootFilesystem
      if (parsedDockerfile.isDistroless && sc?.readOnlyRootFilesystem !== true) {
        findings.push(makeDrift({
          id_code: 'DRIFT-07',
          severity: 'MEDIUM',
          title: `Filesystem hardening dropped: minimal image but no readOnlyRootFilesystem`,
          detail: `Dockerfile uses a minimal base image, implying read-only intent. But ${label}/"${container.name}" does not set readOnlyRootFilesystem:true — attackers can write to the container filesystem.`,
          narrative: 'Dockerfile intent: immutable filesystem via minimal image. K8s reality: writable root filesystem.',
          file: 'Dockerfile ↔ k8s-manifest.yaml',
          cisControl: 'CIS-K8s-5.2.6 / CIS-Docker-4.1',
        }));
      }
    }
  }

  return findings;
}
