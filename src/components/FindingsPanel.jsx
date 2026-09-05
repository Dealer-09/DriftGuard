import React from 'react';
import FindingCard from './FindingCard.jsx';
import ScoreGauge from './ScoreGauge.jsx';

export default function FindingsPanel({
  standaloneFindings,
  driftFindings,
  hardeningScore,
  intentScore,
  verdict,
  scanDuration,
  enriching,
}) {
  const total = standaloneFindings.length + driftFindings.length;
  const driftCount = driftFindings.length;

  const verdictStyle =
    verdict === 'PASS'  ? 'text-green-800 bg-green-50 border-green-200' :
    verdict === 'WARN'  ? 'text-yellow-800 bg-yellow-50 border-yellow-200' :
    verdict === 'FAIL'  ? 'text-red-800 bg-red-50 border-red-200' :
    'text-gray-600 bg-gray-50 border-gray-200';

  return (
    <div className="space-y-6">

      {/* Summary banner */}
      <div className="border border-gray-200 rounded-lg p-4">
        <div className="flex flex-wrap items-start justify-between gap-4">

          {/* Left: verdict + counts */}
          <div className="space-y-2">
            <div className="flex items-center gap-3">
              <span className={`text-xs font-bold uppercase tracking-widest px-2 py-1 border rounded ${verdictStyle}`}>
                {verdict}
              </span>
              {scanDuration != null && (
                <span className="text-xs text-gray-400">{scanDuration}ms</span>
              )}
            </div>
            <p className="text-sm font-semibold text-gray-900">
              {total === 0
                ? '✓ No issues found — configuration looks clean.'
                : `${total} issue${total !== 1 ? 's' : ''} found${driftCount > 0 ? `, ${driftCount} are drift issues your other scanners would miss` : ''}.`
              }
            </p>
            {enriching && (
              <p className="text-xs text-gray-400 flex items-center gap-1">
                <span className="inline-block w-2 h-2 border border-gray-400 border-t-transparent rounded-full animate-spin" />
                Enriching with AI explanations…
              </p>
            )}
          </div>

          {/* Right: gauges */}
          <div className="flex gap-8">
            <ScoreGauge
              label="Hardening Score"
              score={hardeningScore}
              subtitle="CIS standalone checks"
            />
            <ScoreGauge
              label="Intent Preservation"
              score={intentScore}
              subtitle="Drift from Dockerfile intent"
            />
          </div>
        </div>
      </div>

      {/* Drift findings — visually separated */}
      {driftFindings.length > 0 && (
        <div>
          <div className="flex items-center gap-3 mb-3">
            <h3 className="text-xs font-bold uppercase tracking-widest text-indigo-900">
              Drift Findings
            </h3>
            <span className="text-xs text-indigo-600 bg-indigo-50 border border-indigo-100 rounded px-2 py-0.5">
              {driftFindings.length} — where K8s undoes Dockerfile hardening
            </span>
          </div>
          <div className="space-y-1">
            {driftFindings.map(f => (
              <FindingCard key={f.id} finding={f} />
            ))}
          </div>
        </div>
      )}

      {/* Standalone findings */}
      {standaloneFindings.length > 0 && (
        <div>
          <div className="flex items-center gap-3 mb-3">
            <h3 className="text-xs font-bold uppercase tracking-widest text-gray-600">
              Standalone Findings
            </h3>
            <span className="text-xs text-gray-500 bg-gray-100 border border-gray-200 rounded px-2 py-0.5">
              {standaloneFindings.length} — individual file checks
            </span>
          </div>
          <div className="space-y-1">
            {standaloneFindings.map(f => (
              <FindingCard key={f.id} finding={f} />
            ))}
          </div>
        </div>
      )}

      {/* Clean state */}
      {total === 0 && verdict !== null && (
        <div className="text-center py-12 text-gray-400">
          <div className="text-4xl mb-3">✓</div>
          <p className="text-sm font-medium text-gray-600">No misconfigurations detected</p>
          <p className="text-xs text-gray-400 mt-1">Both files pass all CIS-style checks and drift rules.</p>
        </div>
      )}
    </div>
  );
}
