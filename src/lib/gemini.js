/**
 * Gemini API Integration
 * Uses @google/genai SDK with structured JSON output.
 * Two prompt templates:
 *   1. Standalone finding — rule + snippet → explanation + fixedSnippet
 *   2. Drift finding — both snippets + drift narrative → narrative + fixedK8sSnippet
 *
 * Fallback explanations are baked in so a flaky API call never blanks a finding.
 */

import { GoogleGenAI } from '@google/genai';

const MODEL = 'gemini-2.5-flash';

function getClient() {
  const apiKey = import.meta.env.VITE_GEMINI_API_KEY;
  if (!apiKey) return null;
  return new GoogleGenAI({ apiKey });
}

// ─── Fallback explanations (never blank the UI) ───────────────────────────

const FALLBACK_EXPLANATIONS = {
  'DF-01': {
    explanation: 'Running as root means a container breakout gives an attacker full host access. Add a USER instruction with a non-zero UID as the last step of your build.',
    fixedSnippet: '# Add to end of Dockerfile\nRUN addgroup --system app && adduser --system --ingroup app app\nUSER app',
  },
  'DF-02': {
    explanation: 'Unpinned images can silently pull a different version on each build, introducing supply-chain risk. Pin to a specific digest or version tag.',
    fixedSnippet: '# Pin with digest\nFROM node:20.11.0-alpine3.19@sha256:<digest>',
  },
  'DF-03': {
    explanation: 'Hardcoded secrets are baked into the image layer and visible via docker inspect or in any registry that stores the image.',
    fixedSnippet: '# Use build args for secrets (never commit values)\nARG SECRET_KEY\n# Or use Docker BuildKit secret mounts:\nRUN --mount=type=secret,id=mysecret ...',
  },
  'DF-04': {
    explanation: 'ADD has implicit extraction and URL-fetching behaviour that can introduce unintended files. Prefer COPY for local file transfers.',
    fixedSnippet: '# Replace ADD with COPY\nCOPY ./app /app',
  },
  'DF-05': {
    explanation: 'Without HEALTHCHECK, the container orchestrator has no signal of application health and may route traffic to a crashed process.',
    fixedSnippet: 'HEALTHCHECK --interval=30s --timeout=3s --retries=3 \\\n  CMD curl -f http://localhost:8080/health || exit 1',
  },
  'K8S-01': {
    explanation: 'A privileged container has full access to the host kernel — equivalent to running root on the node. Any vulnerability grants complete host takeover.',
    fixedSnippet: 'securityContext:\n  privileged: false\n  allowPrivilegeEscalation: false',
  },
  'K8S-02': {
    explanation: 'Containers without an explicit non-root user run as UID 0, combining container and host root into a single blast radius.',
    fixedSnippet: 'securityContext:\n  runAsNonRoot: true\n  runAsUser: 1000',
  },
  'K8S-03': {
    explanation: 'Without resource limits a single container can exhaust node CPU/memory, causing a Denial of Service for all co-located workloads.',
    fixedSnippet: 'resources:\n  requests:\n    memory: "128Mi"\n    cpu: "100m"\n  limits:\n    memory: "256Mi"\n    cpu: "500m"',
  },
  'K8S-04': {
    explanation: 'An unpinned image tag means each deployment pull may fetch a different image, breaking reproducibility and enabling supply-chain attacks.',
    fixedSnippet: '# Pin to a digest\nimage: myapp@sha256:<digest>',
  },
  'K8S-05': {
    explanation: 'Plain-text secrets in env values are stored unencrypted in the pod spec and etcd, visible to anyone with kubectl get pod -o yaml access.',
    fixedSnippet: 'env:\n  - name: DB_PASSWORD\n    valueFrom:\n      secretKeyRef:\n        name: db-secret\n        key: password',
  },
  'K8S-06a': {
    explanation: 'hostNetwork:true gives the container access to the host network stack, bypassing all Kubernetes NetworkPolicy rules.',
    fixedSnippet: '# Remove or set to false\nhostNetwork: false',
  },
  'K8S-07': {
    explanation: 'Without allowPrivilegeEscalation:false, the container process can gain more privileges than its parent via setuid binaries.',
    fixedSnippet: 'securityContext:\n  allowPrivilegeEscalation: false',
  },
  'K8S-08': {
    explanation: 'A writable root filesystem allows attackers to modify binaries, install persistence, or write malware after gaining code execution.',
    fixedSnippet: 'securityContext:\n  readOnlyRootFilesystem: true',
  },
  'DRIFT-01': {
    explanation: 'The Dockerfile USER instruction is the primary defence against running as root, but Kubernetes overrides it silently. Fix: set securityContext.runAsNonRoot:true and runAsUser matching your Dockerfile USER.',
    fixedSnippet: 'securityContext:\n  runAsNonRoot: true\n  runAsUser: 1000  # Match Dockerfile USER UID',
  },
  'DRIFT-02': {
    explanation: 'hostNetwork:true bypasses the container network namespace entirely — EXPOSE in the Dockerfile becomes irrelevant. Remove hostNetwork or switch to a ClusterIP service.',
    fixedSnippet: '# Remove hostNetwork from pod spec\n# Use a Service instead:\napiVersion: v1\nkind: Service\nspec:\n  type: ClusterIP',
  },
  'DRIFT-03': {
    explanation: 'When the Dockerfile build is pinned but the deployment uses :latest, there is no guarantee the tested image is what runs in production.',
    fixedSnippet: '# Pin the image reference\nimage: myapp:1.2.3\n# Or use digest:\nimage: myapp@sha256:<digest>',
  },
  'DRIFT-04': {
    explanation: 'Dockerfile HEALTHCHECK signals application health to the runtime, but Kubernetes uses its own probe system. Without livenessProbe/readinessProbe, Kubernetes is blind to failures.',
    fixedSnippet: 'livenessProbe:\n  httpGet:\n    path: /health\n    port: 8080\n  initialDelaySeconds: 10\n  periodSeconds: 30\nreadinessProbe:\n  httpGet:\n    path: /ready\n    port: 8080\n  initialDelaySeconds: 5\n  periodSeconds: 10',
  },
  'DRIFT-05': {
    explanation: 'A distroless image has near-zero attack surface by design. Adding capabilities or running privileged completely negates that investment.',
    fixedSnippet: 'securityContext:\n  privileged: false\n  capabilities:\n    drop: ["ALL"]',
  },
  'DRIFT-06': {
    explanation: 'A clean Dockerfile indicates the team knows not to hardcode secrets. Passing them as literal env values in the K8s spec recreates the same risk at the deployment layer.',
    fixedSnippet: 'env:\n  - name: DB_PASSWORD\n    valueFrom:\n      secretKeyRef:\n        name: db-secret\n        key: password',
  },
  'DRIFT-07': {
    explanation: 'A minimal/distroless image implies a read-only filesystem is the intent. Without readOnlyRootFilesystem:true in K8s, the filesystem remains writable.',
    fixedSnippet: 'securityContext:\n  readOnlyRootFilesystem: true\n  # Mount writable dirs explicitly if needed\nvolumeMounts:\n  - name: tmp\n    mountPath: /tmp',
  },
};

// ─── Standalone finding enrichment ───────────────────────────────────────────

export async function enrichFinding(finding) {
  const fallback = FALLBACK_EXPLANATIONS[finding.id_code] || {
    explanation: finding.detail,
    fixedSnippet: '# See CIS control: ' + finding.cisControl,
  };

  const client = getClient();
  if (!client) return { ...finding, ...fallback, aiEnriched: false };

  const prompt = `You are a container security expert. A static analysis tool found this issue:

Rule: ${finding.id_code} — ${finding.title}
Severity: ${finding.severity}
CIS Control: ${finding.cisControl}
Detail: ${finding.detail}

Respond with a JSON object only (no prose wrapper):
{
  "explanation": "<2-sentence plain-English risk explanation for a developer who may not know security>",
  "fixedSnippet": "<corrected Dockerfile or Kubernetes YAML snippet, with comments, ready to copy-paste>"
}`;

  try {
    const ai = client;
    const response = await ai.models.generateContent({
      model: MODEL,
      contents: prompt,
      config: {
        responseMimeType: 'application/json',
        temperature: 0.2,
      },
    });
    const text = response.text;
    const parsed = JSON.parse(text);
    return {
      ...finding,
      explanation: parsed.explanation || fallback.explanation,
      fixedSnippet: parsed.fixedSnippet || fallback.fixedSnippet,
      aiEnriched: true,
    };
  } catch (e) {
    return { ...finding, ...fallback, aiEnriched: false };
  }
}

// ─── Drift finding enrichment ─────────────────────────────────────────────────

export async function enrichDriftFinding(finding, dockerfileSnippet, k8sSnippet) {
  const fallback = FALLBACK_EXPLANATIONS[finding.id_code] || {
    explanation: finding.detail,
    fixedSnippet: '# Fix the K8s securityContext to honour Dockerfile intent',
  };

  const client = getClient();
  if (!client) return { ...finding, ...fallback, aiEnriched: false };

  const prompt = `You are a container security expert specialising in Dockerfile ↔ Kubernetes misconfiguration drift.

A "drift" was detected where the Kubernetes deployment silently undoes security hardening from the Dockerfile.

Drift Rule: ${finding.id_code} — ${finding.title}
Severity: ${finding.severity}
Narrative: ${finding.narrative}

Dockerfile context:
\`\`\`dockerfile
${dockerfileSnippet || '(not provided)'}
\`\`\`

Kubernetes manifest context:
\`\`\`yaml
${k8sSnippet || '(not provided)'}
\`\`\`

Respond with a JSON object only (no prose wrapper). The narrative must follow this framing: "The Dockerfile did X, but the K8s manifest undoes it by Y":
{
  "explanation": "<2-sentence plain-English explanation of the drift and why it's dangerous>",
  "narrative": "<one sentence: 'The Dockerfile hardened X, but the K8s manifest undoes it by Y'>",
  "fixedK8sSnippet": "<corrected Kubernetes YAML securityContext or spec snippet, ready to copy-paste>"
}`;

  try {
    const ai = client;
    const response = await ai.models.generateContent({
      model: MODEL,
      contents: prompt,
      config: {
        responseMimeType: 'application/json',
        temperature: 0.2,
      },
    });
    const text = response.text;
    const parsed = JSON.parse(text);
    return {
      ...finding,
      explanation: parsed.explanation || fallback.explanation,
      narrative: parsed.narrative || finding.narrative,
      fixedSnippet: parsed.fixedK8sSnippet || fallback.fixedSnippet,
      aiEnriched: true,
    };
  } catch (e) {
    return { ...finding, ...fallback, aiEnriched: false };
  }
}

// ─── Batch enrichment ─────────────────────────────────────────────────────────

export async function enrichAllFindings(standaloneFindings, driftFindings, dockerfileContent, k8sContent) {
  const enrichedStandalone = await Promise.all(
    standaloneFindings.map(f => enrichFinding(f))
  );
  const enrichedDrift = await Promise.all(
    driftFindings.map(f => enrichDriftFinding(f, dockerfileContent, k8sContent))
  );
  return { enrichedStandalone, enrichedDrift };
}
