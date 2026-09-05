import React from 'react';

const SEV_STYLES = {
  CRITICAL: 'bg-red-50 text-red-800 border-red-200',
  HIGH:     'bg-orange-50 text-orange-800 border-orange-200',
  MEDIUM:   'bg-yellow-50 text-yellow-800 border-yellow-200',
  LOW:      'bg-gray-100 text-gray-600 border-gray-200',
  INFO:     'bg-gray-50 text-gray-500 border-gray-100',
};

const SEV_DOT = {
  CRITICAL: 'bg-red-600',
  HIGH:     'bg-orange-600',
  MEDIUM:   'bg-yellow-600',
  LOW:      'bg-gray-400',
  INFO:     'bg-gray-300',
};

export default function FindingCard({ finding, defaultOpen = false }) {
  const [open, setOpen] = React.useState(defaultOpen);
  const [copied, setCopied] = React.useState(false);

  const isDrift = finding.category === 'drift';
  const sev = finding.severity || 'LOW';
  const sevStyle = SEV_STYLES[sev] || SEV_STYLES.LOW;

  const handleCopy = () => {
    navigator.clipboard.writeText(finding.fixedSnippet || '').then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  return (
    <div
      className={`border rounded mb-2 overflow-hidden transition-all ${
        isDrift
          ? 'border-indigo-200 bg-indigo-50/30'
          : 'border-gray-200 bg-white'
      }`}
    >
      {/* Header row */}
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full text-left px-4 py-3 flex items-center gap-3 hover:bg-gray-50 transition-colors"
      >
        <span className={`w-2 h-2 rounded-full flex-shrink-0 mt-0.5 ${SEV_DOT[sev] || 'bg-gray-400'}`} />
        <span className="flex-1 font-medium text-gray-900 text-sm leading-snug">
          {finding.title}
        </span>
        <span className="flex items-center gap-2 flex-shrink-0">
          {isDrift && (
            <span className="text-[10px] font-bold uppercase tracking-widest px-1.5 py-0.5 bg-indigo-900 text-indigo-100 rounded">
              DRIFT
            </span>
          )}
          <span className={`text-[10px] font-semibold uppercase tracking-wider px-2 py-0.5 border rounded ${sevStyle}`}>
            {sev}
          </span>
          {finding.cisControl && (
            <span className="text-[10px] text-gray-400 font-mono hidden sm:block">
              {finding.cisControl}
            </span>
          )}
          <span className="text-gray-400 text-xs ml-1">{open ? '▲' : '▼'}</span>
        </span>
      </button>

      {/* Expanded body */}
      {open && (
        <div className="border-t border-gray-100 px-4 py-4 space-y-4">

          {isDrift && finding.narrative && (
            <div className="text-xs font-medium text-indigo-800 bg-indigo-50 border border-indigo-100 rounded px-3 py-2 italic">
              {finding.narrative}
            </div>
          )}

          {finding.explanation && (
            <div>
              <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1">Why it matters</p>
              <p className="text-sm text-gray-700">{finding.explanation}</p>
            </div>
          )}

          {finding.detail && finding.detail !== finding.explanation && (
            <div>
              <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1">Detail</p>
              <p className="text-sm text-gray-600">{finding.detail}</p>
            </div>
          )}

          {/* CVE / attack-class panel */}
          {finding.cves && finding.cves.length > 0 && (
            <div>
              <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">
                Exploit class this misconfiguration enables
              </p>
              <div className="space-y-2">
                {finding.cves.map((cve, i) => {
                  const isVerified = !!cve.cve_id;
                  return (
                    <div
                      key={cve.cve_id || i}
                      className={`rounded px-3 py-2 text-xs border ${
                        isVerified ? 'bg-red-50 border-red-100' : 'bg-gray-50 border-gray-200'
                      }`}
                    >
                      <div className="flex items-center gap-2 mb-1 flex-wrap">
                        {isVerified ? (
                          <a
                            href={cve.nvd_url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="font-bold text-red-700 hover:underline"
                          >
                            {cve.cve_id}
                          </a>
                        ) : (
                          <span className="font-semibold text-gray-500 uppercase tracking-wider text-[10px]">
                            Attack Class
                          </span>
                        )}
                        {isVerified && cve.cvss && (
                          <span className="text-gray-500">CVSS {cve.cvss}</span>
                        )}
                        {cve.attack_technique && (
                          <span className="text-gray-400 italic">{cve.attack_technique}</span>
                        )}
                      </div>
                      <p className="text-gray-600">{cve.summary}</p>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {finding.fixedSnippet && (
            <div>
              <div className="flex items-center justify-between mb-1">
                <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider">
                  Corrected Configuration
                </p>
                <button
                  onClick={handleCopy}
                  className="text-xs text-gray-400 hover:text-gray-700 transition-colors"
                >
                  {copied ? '✓ Copied' : '⧉ Copy'}
                </button>
              </div>
              <pre className="bg-gray-950 text-gray-100 rounded px-4 py-3 text-xs overflow-x-auto whitespace-pre-wrap">
                {finding.fixedSnippet}
              </pre>
            </div>
          )}

          <div className="flex items-center gap-4 pt-1 border-t border-gray-100">
            {finding.file && (
              <span className="text-xs text-gray-400">
                📄 {finding.file}{finding.line ? `:${finding.line}` : ''}
              </span>
            )}
            {finding.cisControl && (
              <span className="text-xs text-gray-400 font-mono">{finding.cisControl}</span>
            )}
            {finding.aiEnriched && (
              <span className="text-xs text-gray-400 ml-auto">✦ AI-enriched</span>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
