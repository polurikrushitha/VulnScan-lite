// VulnScan Lite — Passed & Failed Security Checks Table

import React, { useState } from 'react';
import { CheckCircle2, XCircle, AlertTriangle, Info } from 'lucide-react';
import type { SecurityCheck, CheckStatus } from '../types';

interface CheckTableProps {
  checks: SecurityCheck[];
}

export const CheckTable: React.FC<CheckTableProps> = ({ checks }) => {
  const [filter, setFilter] = useState<'all' | 'passed' | 'failed'>('all');

  const passedCount = checks.filter((c) => c.status === 'passed').length;
  const failedCount = checks.filter((c) => c.status === 'failed').length;

  const filteredChecks = checks.filter((c) => {
    if (filter === 'passed') return c.status === 'passed';
    if (filter === 'failed') return c.status === 'failed';
    return true;
  });

  const renderStatusBadge = (status: CheckStatus) => {
    switch (status) {
      case 'passed':
        return (
          <span className="badge badge-success" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
            <CheckCircle2 size={12} /> Passed
          </span>
        );
      case 'failed':
        return (
          <span className="badge badge-danger" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
            <XCircle size={12} /> Failed
          </span>
        );
      case 'warning':
        return (
          <span className="badge badge-warning" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
            <AlertTriangle size={12} /> Warning
          </span>
        );
      default:
        return (
          <span className="badge badge-info" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
            <Info size={12} /> Info
          </span>
        );
    }
  };

  return (
    <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
      {/* Header & Filter Controls */}
      <div
        style={{
          padding: '1.25rem 1.5rem',
          borderBottom: '1px solid var(--color-border)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '1rem',
        }}
      >
        <div>
          <h3 style={{ fontSize: '1.125rem', fontWeight: 700, color: 'var(--color-text)' }}>
            Security Configuration Checks
          </h3>
          <p style={{ fontSize: '0.8125rem', color: 'var(--color-text-muted)', marginTop: '2px' }}>
            {passedCount} passed &bull; {failedCount} failed of {checks.length} total checks
          </p>
        </div>

        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <button
            type="button"
            className={`btn ${filter === 'all' ? 'btn-primary' : 'btn-outline'}`}
            style={{ padding: '0.375rem 0.875rem', fontSize: '0.75rem' }}
            onClick={() => setFilter('all')}
          >
            All ({checks.length})
          </button>
          <button
            type="button"
            className={`btn ${filter === 'passed' ? 'btn-primary' : 'btn-outline'}`}
            style={{ padding: '0.375rem 0.875rem', fontSize: '0.75rem' }}
            onClick={() => setFilter('passed')}
          >
            Passed ({passedCount})
          </button>
          <button
            type="button"
            className={`btn ${filter === 'failed' ? 'btn-primary' : 'btn-outline'}`}
            style={{ padding: '0.375rem 0.875rem', fontSize: '0.75rem' }}
            onClick={() => setFilter('failed')}
          >
            Failed ({failedCount})
          </button>
        </div>
      </div>

      {/* Table */}
      {filteredChecks.length === 0 ? (
        <div style={{ padding: '3rem 1.5rem', textAlign: 'center', color: 'var(--color-text-muted)' }}>
          No checks matching the selected filter.
        </div>
      ) : (
        <div style={{ overflowX: 'auto' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th style={{ minWidth: '180px' }}>Security Check</th>
                <th>Category</th>
                <th>Status</th>
                <th>Points Impact</th>
                <th style={{ minWidth: '260px' }}>Description</th>
              </tr>
            </thead>
            <tbody>
              {filteredChecks.map((check) => (
                <tr key={check.id}>
                  <td style={{ fontWeight: 600, color: 'var(--color-text)' }}>
                    {check.check_name}
                  </td>
                  <td>
                    <span
                      style={{
                        fontSize: '0.75rem',
                        padding: '2px 8px',
                        borderRadius: '4px',
                        background: 'rgba(255, 255, 255, 0.05)',
                        border: '1px solid var(--color-border)',
                      }}
                    >
                      {check.category}
                    </span>
                  </td>
                  <td>{renderStatusBadge(check.status)}</td>
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
                  <td style={{ color: 'var(--color-text-secondary)', fontSize: '0.8125rem' }}>
                    {check.description || '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

export default CheckTable;
