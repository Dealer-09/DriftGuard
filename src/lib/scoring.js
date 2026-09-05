/**
 * Risk Scoring Engine
 * Calculates a 0.0–10.0 score from normalized findings.
 * Weighted-severity × confidence × type-diversity, log-normalised to 0–10.
 */

export const SEVERITY_WEIGHTS = {
  CRITICAL: 10.0,
  HIGH: 5.0,
  MEDIUM: 2.0,
  LOW: 0.5,
  INFO: 0.0,
};

const CONFIDENCE_MULTIPLIERS = {
  HIGH: 1.0,
  MEDIUM: 0.7,
  LOW: 0.4,
};

/**
 * Calculates a Hardening Score (0–100, higher = better) from standalone findings.
 * Internally uses the same 0–10 risk score as the CLI, then inverts it.
 */
export function calculateHardeningScore(findings) {
  if (!findings || findings.length === 0) return 100;
  const riskScore = calculateRiskScore(findings);
  return Math.round(Math.max(0, 100 - riskScore * 10));
}

/**
 * Calculates an Intent Preservation Score (0–100, higher = better) from drift findings.
 * Drift findings get heavier weight because they represent security intent being undone.
 */
export function calculateIntentPreservationScore(driftFindings) {
  if (!driftFindings || driftFindings.length === 0) return 100;
  // Each drift finding is a hard reversal of intentional hardening — penalise heavily
  const penalty = driftFindings.reduce((acc, f) => {
    const w = SEVERITY_WEIGHTS[f.severity] ?? 2.0;
    return acc + w * 2.5; // 2.5x multiplier vs standalone
  }, 0);
  return Math.round(Math.max(0, 100 - Math.min(100, penalty)));
}

/**
 * Raw 0.0–10.0 risk score using log-normalisation (same as CLI scoring.py).
 */
export function calculateRiskScore(findings) {
  if (!findings || findings.length === 0) return 0;

  let rawScore = 0;
  for (const f of findings) {
    const weight = SEVERITY_WEIGHTS[f.severity] ?? 0;
    const confidence = CONFIDENCE_MULTIPLIERS[f.confidence ?? 'HIGH'] ?? 0.5;
    rawScore += weight * confidence;
  }

  // Type diversity bonus
  const uniqueTypes = new Set(findings.filter(f => f.type !== 'error').map(f => f.type));
  if (uniqueTypes.size > 1) {
    rawScore *= 1.0 + (uniqueTypes.size - 1) * 0.15;
  }

  // log2(1 + raw) * 2 — same formula as scoring.py
  const score = Math.log2(1.0 + rawScore) * 2.0;
  return Math.round(Math.min(10.0, score) * 10) / 10;
}

/**
 * PASS / WARN / FAIL verdict — ported from cli/policy.py
 */
export function evaluateVerdict(findings, driftFindings = []) {
  const all = [...findings, ...driftFindings];
  if (all.length === 0) return 'PASS';
  if (all.some(f => f.severity === 'CRITICAL')) return 'FAIL';
  const score = calculateRiskScore(all);
  if (score >= 5.0) return 'FAIL';
  return 'WARN';
}
