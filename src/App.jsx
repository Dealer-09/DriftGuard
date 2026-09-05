import React, { useState, useCallback } from 'react';
// Styles: index.css + Tailwind (App.css removed — was Vite boilerplate)
import InputPanel from './components/InputPanel.jsx';
import FindingsPanel from './components/FindingsPanel.jsx';
import { parseDockerfile } from './lib/dockerfileParser.js';
import { parseK8sManifest, extractContainers, getPodSecurityContext } from './lib/k8sParser.js';
import { checkDockerfile, checkK8sManifests } from './rules/standalone.js';
import { checkDrift } from './rules/drift.js';
import { calculateHardeningScore, calculateIntentPreservationScore, evaluateVerdict } from './lib/scoring.js';
import { enrichAllFindings } from './lib/gemini.js';

export default function App() {
  const [dockerfile, setDockerfile] = useState('');
  const [k8s, setK8s] = useState('');
  const [scanning, setScanning] = useState(false);
  const [enriching, setEnriching] = useState(false);
  const [result, setResult] = useState(null);

  const handleScan = useCallback(async () => {
    setScanning(true);
    setResult(null);
    const t0 = performance.now();

    try {
      // ── Parse ──
      const parsedDockerfile = dockerfile.trim() ? parseDockerfile(dockerfile) : null;
      const k8sDocs = k8s.trim() ? parseK8sManifest(k8s) : [];

      // ── Rule engines ──
      const dfFindings = parsedDockerfile ? checkDockerfile(parsedDockerfile) : [];
      const k8sFindings = checkK8sManifests(k8sDocs, extractContainers, getPodSecurityContext);
      const driftFindings = (parsedDockerfile && k8sDocs.length > 0)
        ? checkDrift(parsedDockerfile, k8sDocs, extractContainers, getPodSecurityContext)
        : [];

      const standaloneFindings = [...dfFindings, ...k8sFindings];

      // ── Scoring (reused from cli/scoring.py logic) ──
      const hardeningScore = calculateHardeningScore(standaloneFindings);
      const intentScore = calculateIntentPreservationScore(driftFindings);
      const verdict = evaluateVerdict(standaloneFindings, driftFindings);
      const scanDuration = Math.round(performance.now() - t0);

      // Show results immediately with fallback explanations
      setResult({
        standaloneFindings,
        driftFindings,
        hardeningScore,
        intentScore,
        verdict,
        scanDuration,
      });
      setScanning(false);

      // ── AI enrichment (async, non-blocking) ──
      const hasKey = !!import.meta.env.VITE_GEMINI_API_KEY;
      if (hasKey && (standaloneFindings.length + driftFindings.length) > 0) {
        setEnriching(true);
        try {
          const { enrichedStandalone, enrichedDrift } = await enrichAllFindings(
            standaloneFindings,
            driftFindings,
            dockerfile,
            k8s,
          );
          setResult(prev => ({
            ...prev,
            standaloneFindings: enrichedStandalone,
            driftFindings: enrichedDrift,
          }));
        } finally {
          setEnriching(false);
        }
      }
    } catch (e) {
      console.error('Scan error:', e);
      setScanning(false);
      setEnriching(false);
    }
  }, [dockerfile, k8s]);

  return (
    <div className="min-h-screen bg-white">
      {/* Top header */}
      <header className="border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-7 h-7 bg-gray-950 rounded flex items-center justify-center">
              <span className="text-white text-xs font-bold">D</span>
            </div>
            <div>
              <h1 className="text-base font-bold text-gray-950 tracking-tight">DriftGuard</h1>
              <p className="text-xs text-gray-400 leading-none">Container & Kubernetes Misconfiguration Scanner</p>
            </div>
          </div>

          <div className="flex items-center gap-4">
            <span className="hidden sm:block text-xs text-gray-400">
              Powered by Gemini 2.5 Flash
            </span>
            <a
              href="https://github.com/Dealer-09/DriftGuard"
              target="_blank"
              rel="noopener noreferrer"
              className="text-xs text-gray-400 hover:text-gray-700 transition-colors border border-gray-200 rounded px-2 py-1"
            >
              GitHub ↗
            </a>
          </div>
        </div>
      </header>

      {/* Hero tagline */}
      <div className="border-b border-gray-100 bg-gray-50">
        <div className="max-w-7xl mx-auto px-6 py-3">
          <p className="text-xs text-gray-500">
            The only scanner that cross-checks your{' '}
            <span className="font-semibold text-gray-700">Dockerfile</span> against your{' '}
            <span className="font-semibold text-indigo-700">Kubernetes manifest</span> —
            catching where K8s silently undoes your Dockerfile hardening.
          </p>
        </div>
      </div>

      {/* Main content */}
      <main className="max-w-7xl mx-auto px-6 py-8 space-y-8">
        {/* Input section */}
        <section>
          <InputPanel
            dockerfile={dockerfile}
            k8s={k8s}
            onDockerfileChange={setDockerfile}
            onK8sChange={setK8s}
            onScan={handleScan}
            scanning={scanning}
          />
        </section>

        {/* Results section */}
        {result && (
          <section>
            <div className="border-t border-gray-100 pt-8">
              <FindingsPanel
                standaloneFindings={result.standaloneFindings}
                driftFindings={result.driftFindings}
                hardeningScore={result.hardeningScore}
                intentScore={result.intentScore}
                verdict={result.verdict}
                scanDuration={result.scanDuration}
                enriching={enriching}
              />
            </div>
          </section>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-gray-100 mt-16">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <p className="text-xs text-gray-400">
            DriftGuard — Container & Kubernetes Misconfiguration Scanner
          </p>
          <p className="text-xs text-gray-300">
            Built by{' '}
            <a href="https://github.com/Dealer-09" className="text-gray-400 hover:text-gray-600">Dealer-09</a>
            {' '}· Powered by Gemini 2.5 Flash
          </p>
        </div>
      </footer>
    </div>
  );
}
