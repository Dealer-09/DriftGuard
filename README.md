# 🔍 DriftGuard

**Container & Kubernetes Misconfiguration Scanner**

DriftGuard is the only scanner that cross-checks your **Dockerfile** against your **Kubernetes manifest** — catching where K8s silently undoes your Dockerfile security hardening.

---

## The Core Idea

Every other scanner (kube-bench, kubeaudit, Checkov, Kubesec, Trivy) analyses one file at a time. DriftGuard analyses both files **simultaneously** and finds the gap between *what you hardened* and *what actually ships*.

```
Dockerfile says:   USER appuser        (non-root)
K8s manifest says: runAsUser: 0        (root — your hardening is void)
                   ↑ DriftGuard catches this. Others don't.
```

---

## How It Works

```mermaid
flowchart TD
    A([User pastes Dockerfile + K8s YAML]) --> B[Parse]

    B --> B1["dockerfileParser.js\n─────────────────\nLine-by-line regex\nExtracts: USER, FROM,\nEXPOSE, HEALTHCHECK,\nENV, ARG, ADD"]

    B --> B2["k8sParser.js\n─────────────────\njs-yaml multi-doc\nExtracts: containers,\nsecurityContext,\nresources, env, image"]

    B1 --> C1["standalone.js\n─────────────────\nDF-01: No USER\nDF-02: Unpinned image\nDF-03: Hardcoded secret\nDF-04: ADD vs COPY\nDF-05: No HEALTHCHECK"]

    B2 --> C2["standalone.js\n─────────────────\nK8S-01: privileged\nK8S-02: Running as root\nK8S-03: No resource limits\nK8S-04: :latest tag\nK8S-05: Literal secrets\nK8S-06: hostNetwork/PID/IPC\nK8S-07: allowPrivEscalation\nK8S-08: No readOnlyRootFS"]

    B1 --> C3["drift.js ⭐\n─────────────────\nDRIFT-01: USER override\nDRIFT-02: Network bypass\nDRIFT-03: Image drift\nDRIFT-04: Probes dropped\nDRIFT-05: Capability creep\nDRIFT-06: Secret hygiene\nDRIFT-07: FS hardening"]
    B2 --> C3

    C1 --> D["scoring.js\n─────────────────\nHardening Score 0–100\nIntent Preservation 0–100\nVerdict: PASS / WARN / FAIL"]
    C2 --> D
    C3 --> D

    D --> E["cveMap.js\n─────────────────\nEnrich with CVEs\nand Attack Classes\nMITRE ATT&CK tags"]

    E --> F{Gemini API key set?}

    F -- Yes --> G["gemini.js\n─────────────────\nGemini 2.5 Flash\nJSON structured output\n2 prompt templates:\n• Standalone finding\n• Drift finding"]

    F -- No --> H["Hardcoded Fallbacks\n─────────────────\nPer-rule explanations\nbaked in — demo\nnever goes blank"]

    G --> I([Results rendered in UI])
    H --> I

    I --> J["FindingsPanel\n─────────────────\nScore Gauges\nDrift section first\nStandalone section\nVerdict banner"]

    J --> K["FindingCard × N\n─────────────────\nCollapsible card\nSeverity + CIS ID\nCVE / Attack Class\nAI explanation\nCopy-ready fix"]

    style C3 fill:#e8e8f0,stroke:#4444aa,color:#1a1a2e
    style A fill:#f5f5f5,stroke:#222,color:#111
    style I fill:#f5f5f5,stroke:#222,color:#111
    style G fill:#f0f0f0,stroke:#555,color:#111
```

### Two-phase UX

```mermaid
sequenceDiagram
    actor User
    participant Parser
    participant RuleEngine
    participant UI
    participant Gemini

    User->>Parser: Paste Dockerfile + YAML → Scan
    Parser->>RuleEngine: Parsed artifacts
    RuleEngine->>UI: Findings + scores (< 10ms)
    Note over UI: Results shown instantly<br/>with fallback explanations

    RuleEngine->>Gemini: Enrich all findings async
    Gemini-->>UI: AI explanations + fix snippets
    Note over UI: Cards update in place<br/>✦ AI-enriched badge appears
```

---

## Features

### Drift Engine ⭐ (unique)
7 cross-artifact rules that detect security intent reversals:

| Rule | What it catches |
|------|----------------|
| `DRIFT-01` | Dockerfile `USER` → K8s runs as root |
| `DRIFT-02` | Dockerfile `EXPOSE` → K8s `hostNetwork:true` nullifies it |
| `DRIFT-03` | Dockerfile FROM pinned → K8s deploys `:latest` |
| `DRIFT-04` | Dockerfile `HEALTHCHECK` → K8s has no probes |
| `DRIFT-05` | Distroless image → K8s adds capabilities |
| `DRIFT-06` | Dockerfile has no secrets → K8s injects literal secrets |
| `DRIFT-07` | Minimal image → K8s missing `readOnlyRootFilesystem` |

### Standalone Rule Engine
13 CIS-mapped checks across both files:
- **Dockerfile:** No USER, unpinned base, hardcoded secrets, ADD vs COPY, no HEALTHCHECK
- **Kubernetes:** privileged mode, root user, missing resource limits, `:latest` image, literal secrets, hostNetwork/hostPID/hostIPC, allowPrivilegeEscalation, missing readOnlyRootFilesystem

### Two Scores
- **Hardening Score** — How well individual files follow CIS best practices (0–100)
- **Intent Preservation Score** — How well K8s honours Dockerfile security intent (0–100)

### CVE Correlation
Each finding is enriched with verified CVEs or attack-class entries that the misconfiguration enables — CVE ID, CVSS score, exploit summary, and MITRE ATT&CK technique tag.

### Gemini AI Enrichment
Gemini 2.5 Flash generates:
- Plain-English explanation of each risk
- A corrected configuration snippet (copy-ready)
- For drift findings: a narrative of *"The Dockerfile did X, but K8s undoes it by Y"*

Results appear instantly with fallback explanations — AI enrichment updates them async so a flaky API call never breaks a demo.

---

## Getting Started

### Prerequisites
- [Bun](https://bun.sh) (runtime + package manager)
- A [Gemini API key](https://aistudio.google.com/)

### Setup

```bash
git clone https://github.com/Dealer-09/DriftGuard
cd DriftGuard

bun install

# Add your Gemini API key
cp .env.example .env
# Edit .env → VITE_GEMINI_API_KEY=your_key_here

bun run dev
```

Open `http://localhost:5173` and click **Load demo files** to see the drift engine in action.

---

## Test Scenarios

The `test/` directory has 7 ready-to-paste scenario pairs:

| Folder | What it tests |
|---|---|
| `01-all-clean/` | Perfect config — Score 100/100, Verdict PASS |
| `02-dockerfile-issues/` | All 5 Dockerfile standalone rules firing |
| `03-k8s-issues/` | All 8 K8s standalone rules firing |
| `04-drift-full/` | All 7 drift rules firing simultaneously |
| `05-minimal-drift-demo/` | Just DRIFT-01 + DRIFT-03 — best for a quick live demo |
| `06-real-world-node/` | Realistic Node.js microservice — subtle real issues |
| `07-real-world-python/` | Realistic FastAPI service — multi-doc YAML with HPA |

---

## Project Structure

```
DriftGuard/
├── src/
│   ├── lib/
│   │   ├── scoring.js          # Risk scoring engine
│   │   ├── dockerfileParser.js # Line-based regex parser
│   │   ├── k8sParser.js        # js-yaml multi-doc parser
│   │   ├── gemini.js           # Gemini 2.5 Flash, JSON output + fallbacks
│   │   └── cveMap.js           # Misconfiguration → CVE / attack-class map
│   ├── rules/
│   │   ├── standalone.js       # 13 Dockerfile + K8s checks
│   │   └── drift.js            # 7 cross-artifact drift rules ⭐
│   ├── components/
│   │   ├── InputPanel.jsx
│   │   ├── FindingCard.jsx     # Collapsible card with CVE panel + copy button
│   │   ├── ScoreGauge.jsx      # SVG circular score gauge
│   │   └── FindingsPanel.jsx   # Summary banner + two separated sections
│   └── App.jsx
├── test/                       # 7 test scenario pairs (Dockerfile + k8s.yaml)
├── fixtures/                   # Demo files for live demo
└── .env.example
```

---

## Tech Stack

| Layer | Choice |
|-------|--------|
| Runtime / Package manager | Bun 1.4 |
| Bundler | Vite 8 + Rolldown |
| UI | React 19 |
| Styling | Tailwind CSS v4 |
| YAML parsing | js-yaml |
| AI | Gemini 2.5 Flash via @google/genai |

---

## Scoring

```
risk_score        = log2(1 + weighted_sum) × 2     capped at 10.0
hardening_score   = max(0, 100 - risk_score × 10)
intent_score      = max(0, 100 - drift_penalty)    (2.5× weight vs standalone)
```

Severity weights: `CRITICAL=10, HIGH=5, MEDIUM=2, LOW=0.5`

---

*Built by [Dealer-09](https://github.com/Dealer-09)*
