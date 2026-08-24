// VulnScan Lite — Vulnerability Finding Card

import React from 'react';
import {
  AlertCircle,
  ShieldAlert,
  AlertTriangle,
  Info,
  CheckCircle,
  Globe,
  HelpCircle,
  Terminal,
  AlertOctagon,
} from 'lucide-react';
import type { Finding, FindingSeverity } from '../types';

interface FindingCardProps {
  finding: Finding;
}

export const getSeverityColor = (severity: FindingSeverity): string => {
  switch (severity) {
    case 'critical':
      return 'var(--color-danger)';
    case 'high':
      return '#ea580c';
    case 'medium':
      return 'var(--color-warning)';
    case 'low':
      return 'var(--color-info)';
    default:
      return 'var(--color-text-secondary)';
  }
};

const getSeverityIcon = (severity: FindingSeverity) => {
  switch (severity) {
    case 'critical':
      return <ShieldAlert size={18} />;
    case 'high':
      return <AlertCircle size={18} />;
    case 'medium':
      return <AlertTriangle size={18} />;
    case 'low':
      return <Info size={18} />;
    default:
      return <CheckCircle size={18} />;
  }
};

export const FindingCard: React.FC<FindingCardProps> = ({ finding }) => {
  const color = getSeverityColor(finding.severity);

  // Normalize confidence to single clean string: High, Medium, or Low
  const rawConf = (finding.confidence || 'high').toLowerCase().trim();
  const normalizedConfidence =
    rawConf.includes('high') ? 'High' : rawConf.includes('medium') ? 'Medium' : 'Low';

  return (
    <article
      className="card"
      style={{
        borderLeft: `4px solid ${color}`,
        display: 'flex',
        flexDirection: 'column',
        gap: '0.875rem',
      }}
    >
      {/* Header: Title, Severity, Normalized Confidence */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'flex-start',
          flexWrap: 'wrap',
          gap: '0.5rem',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <span style={{ color }}>{getSeverityIcon(finding.severity)}</span>
          <h4 style={{ fontSize: '1.0625rem', fontWeight: 700, color: 'var(--color-text)', margin: 0 }}>
            {finding.check_name}
          </h4>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <span
            className="badge"
            style={{
              background: 'var(--color-bg-secondary)',
              color: 'var(--color-text-secondary)',
              border: '1px solid var(--color-border)',
              fontSize: '0.75rem',
            }}
          >
            Confidence: {normalizedConfidence}
          </span>

          <span
            className="badge"
            style={{
              background: `${color}18`,
              color,
              border: `1px solid ${color}40`,
              display: 'inline-flex',
              alignItems: 'center',
              gap: '4px',
              textTransform: 'uppercase',
              fontWeight: 700,
              fontSize: '0.75rem',
            }}
          >
            {finding.severity}
          </span>
        </div>
      </div>

      {/* Meta: Category & Affected URL */}
      <div
        style={{
          display: 'flex',
          flexWrap: 'wrap',
          gap: '1rem',
          fontSize: '0.8125rem',
          color: 'var(--color-text-muted)',
        }}
      >
        {finding.category && (
          <span style={{ textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Category: <strong style={{ color: 'var(--color-text-secondary)' }}>{finding.category}</strong>
          </span>
        )}
        {finding.affected_url && (
          <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
            <Globe size={13} /> Target:{' '}
            <code style={{ color: 'var(--color-text)', fontSize: '0.75rem' }}>{finding.affected_url}</code>
          </span>
        )}
      </div>

      {/* Description */}
      <p style={{ fontSize: '0.9375rem', color: 'var(--color-text-secondary)', lineHeight: 1.6, margin: 0 }}>
        {finding.description}
      </p>

      {/* Why This Matters / Security Impact */}
      {finding.impact && (
        <div
          style={{
            background: 'var(--color-bg-secondary)',
            border: '1px solid var(--color-border)',
            borderRadius: 'var(--radius-sm)',
            padding: '0.75rem 1rem',
            fontSize: '0.8125rem',
          }}
        >
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '4px',
              fontWeight: 600,
              color: 'var(--color-text)',
              marginBottom: '0.25rem',
            }}
          >
            <AlertOctagon size={14} color="var(--color-warning)" /> Why this matters:
          </div>
          <div style={{ color: 'var(--color-text-secondary)', lineHeight: 1.5 }}>
            {finding.impact}
          </div>
        </div>
      )}

      {/* Safe Evidence */}
      {finding.evidence && (
        <div
          style={{
            background: 'var(--color-bg-secondary)',
            border: '1px solid var(--color-border)',
            borderRadius: 'var(--radius-sm)',
            padding: '0.75rem 1rem',
            fontSize: '0.8125rem',
          }}
        >
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '4px',
              fontWeight: 600,
              color: 'var(--color-text)',
              marginBottom: '0.25rem',
            }}
          >
            <HelpCircle size={14} color="var(--color-accent)" /> Evidence / Trigger:
          </div>
          <div style={{ color: 'var(--color-text)', fontFamily: 'var(--font-mono)', fontSize: '0.75rem', wordBreak: 'break-all' }}>
            {finding.evidence}
          </div>
        </div>
      )}

      {/* Remediation Guidance */}
      {finding.remediation && (
        <div
          style={{
            marginTop: '0.25rem',
            background: 'rgba(99, 102, 241, 0.05)',
            border: '1px solid rgba(99, 102, 241, 0.2)',
            borderRadius: 'var(--radius-md)',
            padding: '0.875rem 1rem',
          }}
        >
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '4px',
              fontSize: '0.8125rem',
              fontWeight: 600,
              color: 'var(--color-accent)',
              marginBottom: '0.375rem',
            }}
          >
            <Terminal size={14} /> Recommended Remediation
          </div>
          <pre
            style={{
              fontSize: '0.8125rem',
              color: 'var(--color-text)',
              fontFamily: 'var(--font-mono)',
              whiteSpace: 'pre-wrap',
              margin: 0,
            }}
          >
            {finding.remediation}
          </pre>
          <div style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)', marginTop: '0.5rem', fontStyle: 'italic' }}>
            Note: Remediation snippets provide baseline guidance. Adjust directives and configurations to match your application requirements.
          </div>
        </div>
      )}
    </article>
  );
};

export default FindingCard;
