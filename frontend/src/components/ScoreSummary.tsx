// VulnScan Lite — Executive Score Summary & Risk Classification Component

import React from 'react';
import { Globe, Calendar, Clock, ShieldCheck, AlertCircle, ShieldAlert, AlertTriangle, Info, CheckCircle2, Hash } from 'lucide-react';
import type { Grade, RiskLevel, Finding } from '../types';
import { getGradeColor } from './ScoreGauge';

interface ScoreSummaryProps {
  score?: number;
  grade?: Grade;
  riskLevel?: RiskLevel | string;
  targetUrl: string;
  scanId: string;
  status: string;
  createdAt: string;
  completedAt?: string;
  startedAt?: string;
  durationSeconds?: number;
  findings?: Finding[];
}

export const getCalculatedRiskLevel = (score?: number): RiskLevel => {
  if (typeof score !== 'number' || isNaN(score)) return 'Moderate';
  if (score >= 90) return 'Excellent';
  if (score >= 80) return 'Good';
  if (score >= 65) return 'Moderate';
  if (score >= 50) return 'Needs Improvement';
  return 'Poor';
};

export const getRiskInterpretation = (risk: RiskLevel | string): string => {
  switch (risk) {
    case 'Excellent':
      return 'Excellent baseline security posture. Key defense-in-depth headers and valid TLS encryption observed.';
    case 'Good':
      return 'Good security configuration with minor defense-in-depth improvements recommended.';
    case 'Moderate':
      return 'Moderate security posture. Several recommended security headers or configurations are missing.';
    case 'Needs Improvement':
      return 'Multiple security configuration weaknesses detected requiring administrative attention.';
    case 'Poor':
      return 'Critical security weaknesses identified (e.g. unencrypted HTTP transport or invalid SSL certificate).';
    default:
      return 'Passive security analysis completed.';
  }
};

export const ScoreSummary: React.FC<ScoreSummaryProps> = ({
  score,
  grade,
  riskLevel,
  targetUrl,
  scanId,
  status,
  createdAt,
  completedAt,
  startedAt,
  durationSeconds,
  findings = [],
}) => {
  const gradeColor = getGradeColor(grade);
  const effectiveRisk: RiskLevel | string = riskLevel || getCalculatedRiskLevel(score);
  const interpretation = getRiskInterpretation(effectiveRisk);

  // Compute duration
  let durationStr = '—';
  if (typeof durationSeconds === 'number') {
    durationStr = `${durationSeconds.toFixed(2)}s`;
  } else if (startedAt && completedAt) {
    const ms = new Date(completedAt).getTime() - new Date(startedAt).getTime();
    if (ms > 0) {
      durationStr = `${(ms / 1000).toFixed(2)}s`;
    }
  }

  const criticalCount = findings.filter((f) => f.severity === 'critical').length;
  const highCount = findings.filter((f) => f.severity === 'high').length;
  const mediumCount = findings.filter((f) => f.severity === 'medium').length;
  const lowCount = findings.filter((f) => f.severity === 'low').length;
  const infoCount = findings.filter((f) => f.severity === 'info').length;

  return (
    <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* Title & Grade Badge */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <span style={{ fontSize: '0.8125rem', color: 'var(--color-accent)', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 700 }}>
            Executive Summary &bull; Risk Level: {effectiveRisk}
          </span>
          <h3 style={{ fontSize: '1.25rem', fontWeight: 700, marginTop: '0.25rem', color: 'var(--color-text)' }}>
            {interpretation}
          </h3>
        </div>

        {grade && (
          <div
            className="grade-badge"
            style={{
              background: `${gradeColor}20`,
              color: gradeColor,
              border: `1px solid ${gradeColor}50`,
              boxShadow: `0 0 20px ${gradeColor}25`,
              fontSize: '1.75rem',
              minWidth: '56px',
              height: '56px',
            }}
          >
            {grade}
          </div>
        )}
      </div>

      {/* Metadata Grid */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
          gap: '0.875rem',
          padding: '1rem',
          background: 'var(--color-bg-secondary)',
          borderRadius: 'var(--radius-md)',
          fontSize: '0.875rem',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Globe size={15} color="var(--color-primary)" />
          <span style={{ color: 'var(--color-text-muted)' }}>Target:</span>
          <strong style={{ color: 'var(--color-text)', wordBreak: 'break-all' }}>{targetUrl}</strong>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Hash size={15} color="var(--color-accent)" />
          <span style={{ color: 'var(--color-text-muted)' }}>Scan ID:</span>
          <strong style={{ color: 'var(--color-text)', fontFamily: 'var(--font-mono)', fontSize: '0.75rem' }}>
            {scanId.length > 12 ? `${scanId.substring(0, 12)}...` : scanId}
          </strong>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Calendar size={15} color="var(--color-accent)" />
          <span style={{ color: 'var(--color-text-muted)' }}>Scanned:</span>
          <strong style={{ color: 'var(--color-text)' }}>
            {createdAt ? new Date(createdAt).toLocaleString() : '—'}
          </strong>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Clock size={15} color="var(--color-warning)" />
          <span style={{ color: 'var(--color-text-muted)' }}>Duration:</span>
          <strong style={{ color: 'var(--color-text)' }}>{durationStr}</strong>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <ShieldCheck size={15} color={gradeColor} />
          <span style={{ color: 'var(--color-text-muted)' }}>Score:</span>
          <strong style={{ color: gradeColor }}>
            {typeof score === 'number' && !isNaN(score) ? `${score.toFixed(1)} / 100` : 'N/A'}
          </strong>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <CheckCircle2 size={15} color="var(--color-success)" />
          <span style={{ color: 'var(--color-text-muted)' }}>Status:</span>
          <span className="badge badge-success" style={{ textTransform: 'capitalize', fontSize: '0.75rem' }}>
            {status}
          </span>
        </div>
      </div>

      {/* Severity Breakdown Strip */}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem', alignItems: 'center' }}>
        <span style={{ fontSize: '0.8125rem', color: 'var(--color-text-muted)', fontWeight: 600, marginRight: '0.25rem' }}>
          Total Findings ({findings.length}):
        </span>
        <span className="badge" style={{ background: 'rgba(239, 68, 68, 0.15)', color: 'var(--color-danger)', border: '1px solid rgba(239, 68, 68, 0.3)', fontSize: '0.75rem' }}>
          <ShieldAlert size={12} style={{ marginRight: '3px' }} /> Critical: {criticalCount}
        </span>
        <span className="badge" style={{ background: 'rgba(234, 88, 12, 0.15)', color: '#ea580c', border: '1px solid rgba(234, 88, 12, 0.3)', fontSize: '0.75rem' }}>
          <AlertCircle size={12} style={{ marginRight: '3px' }} /> High: {highCount}
        </span>
        <span className="badge" style={{ background: 'rgba(245, 158, 11, 0.15)', color: 'var(--color-warning)', border: '1px solid rgba(245, 158, 11, 0.3)', fontSize: '0.75rem' }}>
          <AlertTriangle size={12} style={{ marginRight: '3px' }} /> Medium: {mediumCount}
        </span>
        <span className="badge" style={{ background: 'rgba(59, 130, 246, 0.15)', color: 'var(--color-info)', border: '1px solid rgba(59, 130, 246, 0.3)', fontSize: '0.75rem' }}>
          <Info size={12} style={{ marginRight: '3px' }} /> Low: {lowCount}
        </span>
        <span className="badge" style={{ background: 'rgba(148, 163, 184, 0.15)', color: 'var(--color-text-secondary)', border: '1px solid rgba(148, 163, 184, 0.3)', fontSize: '0.75rem' }}>
          <CheckCircle2 size={12} style={{ marginRight: '3px' }} /> Info: {infoCount}
        </span>
      </div>

      {/* Passive Analysis Disclaimer */}
      <p style={{ fontSize: '0.8125rem', color: 'var(--color-text-muted)', lineHeight: 1.5, margin: 0 }}>
        <AlertCircle size={14} style={{ display: 'inline', marginRight: '4px', verticalAlign: 'text-bottom' }} />
        VulnScan Lite detected security configuration weaknesses through passive external analysis. A high score reflects baseline configuration health, but does not prove the target is entirely free from vulnerabilities.
      </p>
    </div>
  );
};

export default ScoreSummary;
