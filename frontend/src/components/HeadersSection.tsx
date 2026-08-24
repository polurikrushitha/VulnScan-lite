// VulnScan Lite — HTTP Security Headers Section

import React from 'react';
import { Shield, CheckCircle2, XCircle, Server, Info } from 'lucide-react';
import type { HeaderData } from '../types';

interface HeadersSectionProps {
  headerData?: HeaderData;
}

export const HeadersSection: React.FC<HeadersSectionProps> = ({ headerData }) => {
  if (!headerData || !headerData.checks) {
    return (
      <div className="card" style={{ color: 'var(--color-text-muted)', textAlign: 'center', padding: '2rem' }}>
        Security headers data is unavailable for this scan.
      </div>
    );
  }

  return (
    <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Shield size={20} color="var(--color-primary)" />
          <h4 style={{ fontSize: '1.125rem', fontWeight: 700, color: 'var(--color-text)' }}>
            HTTP Security Headers
          </h4>
        </div>
      </div>

      {/* Server & Technology Metadata */}
      {(headerData.server || headerData.x_powered_by) && (
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '1.5rem',
            padding: '0.875rem 1rem',
            background: 'var(--color-bg-secondary)',
            borderRadius: 'var(--radius-md)',
            fontSize: '0.8125rem',
            flexWrap: 'wrap',
          }}
        >
          {headerData.server && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Server size={16} color="var(--color-primary)" />
              <span style={{ color: 'var(--color-text-muted)' }}>Server:</span>
              <strong style={{ color: 'var(--color-text)' }}>{headerData.server}</strong>
            </div>
          )}
          {headerData.x_powered_by && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Info size={16} color="var(--color-accent)" />
              <span style={{ color: 'var(--color-text-muted)' }}>X-Powered-By:</span>
              <strong style={{ color: 'var(--color-text)' }}>{headerData.x_powered_by}</strong>
            </div>
          )}
          <span style={{ color: 'var(--color-text-muted)', fontSize: '0.75rem', marginLeft: 'auto' }}>
            Technology headers are informational and do not by themselves prove a vulnerability.
          </span>
        </div>
      )}

      {/* Scored & Bonus Headers Table */}
      <div style={{ overflowX: 'auto' }}>
        <table className="data-table">
          <thead>
            <tr>
              <th style={{ minWidth: '200px' }}>Header Name</th>
              <th>Status</th>
              <th>Points Impact</th>
              <th style={{ minWidth: '240px' }}>Detected Value / Detail</th>
            </tr>
          </thead>
          <tbody>
            {headerData.checks.map((check) => (
              <tr key={check.header_name}>
                <td style={{ fontWeight: 600, color: 'var(--color-text)' }}>
                  {check.header_name}
                </td>
                <td>
                  {check.present ? (
                    <span className="badge badge-success" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                      <CheckCircle2 size={12} /> Present
                    </span>
                  ) : (
                    <span className="badge badge-danger" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                      <XCircle size={12} /> Missing
                    </span>
                  )}
                </td>
                <td>
                  <span
                    style={{
                      fontWeight: 700,
                      color: check.points > 0 ? 'var(--color-success)' : check.points < 0 ? 'var(--color-danger)' : 'var(--color-text-muted)',
                    }}
                  >
                    {check.points > 0 ? `+${check.points}` : check.points}
                  </span>
                </td>
                <td style={{ fontSize: '0.8125rem' }}>
                  {check.value ? (
                    <code
                      style={{
                        fontFamily: 'var(--font-mono)',
                        color: 'var(--color-accent)',
                        background: 'rgba(34, 211, 238, 0.08)',
                        padding: '2px 6px',
                        borderRadius: '4px',
                        wordBreak: 'break-all',
                      }}
                    >
                      {check.value}
                    </code>
                  ) : (
                    <span style={{ color: 'var(--color-text-secondary)' }}>{check.description}</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default HeadersSection;
