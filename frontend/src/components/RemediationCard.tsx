// VulnScan Lite — Detailed Remediation Guide Card

import React from 'react';
import { Wrench, Terminal, HelpCircle, CheckCheck } from 'lucide-react';
import type { Finding } from '../types';

interface RemediationCardProps {
  findings: Finding[];
}

export const RemediationCard: React.FC<RemediationCardProps> = ({ findings }) => {
  const actionableFindings = findings.filter((f) => !!f.remediation);

  if (actionableFindings.length === 0) {
    return (
      <div className="card" style={{ textAlign: 'center', padding: '3rem 1.5rem', color: 'var(--color-text-muted)' }}>
        <CheckCheck size={40} style={{ color: 'var(--color-success)', margin: '0 auto 0.75rem' }} />
        <h4 style={{ fontSize: '1.125rem', fontWeight: 600, color: 'var(--color-text)' }}>No Pending Remediation</h4>
        <p style={{ fontSize: '0.875rem', marginTop: '0.25rem' }}>
          All scanned baseline security checks satisfied recommended practices.
        </p>
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {actionableFindings.map((finding) => (
        <div key={finding.id} className="card" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Wrench size={20} color="var(--color-accent)" />
            <h4 style={{ fontSize: '1.125rem', fontWeight: 700, color: 'var(--color-text)' }}>
              Remediation: {finding.check_name}
            </h4>
          </div>

          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem', fontSize: '0.8125rem', fontWeight: 600, color: 'var(--color-text-secondary)', marginBottom: '0.25rem' }}>
              <HelpCircle size={14} /> Why this matters:
            </div>
            <p style={{ fontSize: '0.875rem', color: 'var(--color-text-secondary)', lineHeight: 1.6 }}>
              {finding.description}
            </p>
          </div>

          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem', fontSize: '0.8125rem', fontWeight: 600, color: 'var(--color-accent)', marginBottom: '0.5rem' }}>
              <Terminal size={14} /> Recommended Configuration:
            </div>
            <div
              style={{
                background: 'var(--color-bg-secondary)',
                border: '1px solid var(--color-border)',
                borderRadius: 'var(--radius-md)',
                padding: '1rem',
                overflowX: 'auto',
              }}
            >
              <pre
                style={{
                  margin: 0,
                  fontSize: '0.8125rem',
                  fontFamily: 'var(--font-mono)',
                  color: 'var(--color-text)',
                  lineHeight: 1.5,
                }}
              >
                {finding.remediation}
              </pre>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
};

export default RemediationCard;
