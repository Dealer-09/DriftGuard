import React from 'react';

/**
 * ScoreGauge — circular progress gauge showing 0–100 score.
 * Uses SVG stroke-dashoffset for the arc.
 */
export default function ScoreGauge({ label, score, subtitle, color = '#111111' }) {
  const radius = 42;
  const circumference = 2 * Math.PI * radius;
  const filled = ((score ?? 0) / 100) * circumference;
  const dash = `${filled} ${circumference - filled}`;

  // Color based on score threshold — muted, not neon
  const arcColor =
    score >= 80 ? '#2d6a4f'   // dark green
    : score >= 50 ? '#b8860b' // amber
    : '#c0392b';               // muted red

  return (
    <div className="flex flex-col items-center gap-2">
      <svg width="110" height="110" viewBox="0 0 110 110">
        {/* Background track */}
        <circle
          cx="55" cy="55" r={radius}
          fill="none"
          stroke="#e5e5e5"
          strokeWidth="8"
        />
        {/* Score arc */}
        <circle
          cx="55" cy="55" r={radius}
          fill="none"
          stroke={arcColor}
          strokeWidth="8"
          strokeDasharray={dash}
          strokeDashoffset={circumference / 4} /* start from top */
          strokeLinecap="round"
          style={{ transition: 'stroke-dasharray 0.8s ease' }}
        />
        {/* Score number */}
        <text x="55" y="52" textAnchor="middle" fontSize="20" fontWeight="700" fill={arcColor}>
          {score ?? '--'}
        </text>
        <text x="55" y="66" textAnchor="middle" fontSize="9" fill="#aaaaaa">
          / 100
        </text>
      </svg>

      <div className="text-center">
        <p className="text-sm font-semibold text-gray-900">{label}</p>
        {subtitle && (
          <p className="text-xs text-gray-400 mt-0.5 max-w-[130px] text-center">{subtitle}</p>
        )}
      </div>
    </div>
  );
}
