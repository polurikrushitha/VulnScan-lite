// VulnScan Lite — Full Scan History Page

import React, { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { History as HistoryIcon, PlusCircle, AlertCircle, ExternalLink, Shield, RotateCcw } from 'lucide-react';
import { getScanHistory } from '../services/scanService';
import type { ScanHistoryItem } from '../types';
import { formatApiError } from '../services/api';
import { SecurityDisclaimer } from '../components/SecurityDisclaimer';

export const History: React.FC = () => {
  const navigate = useNavigate();
  const [history, setHistory] = useState<ScanHistoryItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string>('');

  useEffect(() => {
    let isMounted = true;

    const fetchHistory = async () => {
      try {
        setLoading(true);
        setError('');
        const data = await getScanHistory();
        if (isMounted) {
          setHistory(Array.isArray(data) ? data : []);
        }
      } catch (err: any) {
        if (isMounted) {
          setError(formatApiError(err));
        }
      } finally {
        if (isMounted) {
          setLoading(false);
        }
      }
    };

    fetchHistory();

    return () => {
      isMounted = false;
    };
  }, []);

  const handleScanAgain = (targetUrl: string) => {
    navigate('/scan', { state: { initialUrl: targetUrl } });
  };

  const safeHistory = Array.isArray(history) ? history : [];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h1 style={{ fontSize: '2rem', fontWeight: 800, color: 'var(--color-text)' }}>
            Scan History
          </h1>
          <p style={{ color: 'var(--color-text-secondary)', fontSize: '0.9375rem', marginTop: '0.25rem' }}>
            Review past security audit records, findings summaries, and diagnostic reports
          </p>
        </div>

        <Link to="/scan" className="btn btn-primary" style={{ padding: '0.625rem 1.25rem', fontSize: '0.9375rem' }}>
          <PlusCircle size={18} /> New Scan
        </Link>
      </div>

      <SecurityDisclaimer />

      {/* Scans Clean Data Table */}
      <div>
        <h3 className="section-title">
          <HistoryIcon size={20} /> All Recorded Scans ({safeHistory.length})
        </h3>

        {loading ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: '4rem 0' }}>
            <div className="spinner" />
          </div>
        ) : error ? (
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem',
              color: 'var(--color-danger)',
              padding: '1.5rem',
              background: 'rgba(239, 68, 68, 0.1)',
              borderRadius: 'var(--radius-md)',
            }}
          >
            <AlertCircle size={20} /> {error}
          </div>
        ) : safeHistory.length === 0 ? (
          <div className="card" style={{ textAlign: 'center', padding: '4rem 2rem' }}>
            <Shield size={48} style={{ margin: '0 auto 1rem', opacity: 0.35, color: 'var(--color-primary)' }} />
            <h4 style={{ fontSize: '1.125rem', fontWeight: 700, marginBottom: '0.5rem' }}>No scan history found</h4>
            <p style={{ color: 'var(--color-text-secondary)', marginBottom: '1.5rem' }}>
              Run your first vulnerability scan to see results here.
            </p>
            <Link to="/scan" className="btn btn-primary">
              <PlusCircle size={18} /> Start New Scan
            </Link>
          </div>
        ) : (
          <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
            <div style={{ overflowX: 'auto' }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th style={{ minWidth: '240px' }}>Target URL</th>
                    <th>Status</th>
                    <th>Findings</th>
                    <th>Date &amp; Time</th>
                    <th style={{ textAlign: 'right' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {safeHistory.map((scan) => (
                    <tr key={scan.scan_id}>
                      <td style={{ fontWeight: 600, color: 'var(--color-text)' }}>
                        <span style={{ wordBreak: 'break-all' }}>{scan.target_url}</span>
                      </td>
                      <td>
                        <span
                          className={`badge ${
                            scan.status === 'completed'
                              ? 'badge-success'
                              : scan.status === 'failed'
                              ? 'badge-danger'
                              : 'badge-info'
                          }`}
                        >
                          {scan.status}
                        </span>
                      </td>
                      <td>
                        {scan.status === 'completed' ? (
                          <span
                            style={{
                              fontWeight: 700,
                              color: (scan.findings_count || 0) > 0 ? 'var(--color-warning)' : 'var(--color-success)',
                            }}
                          >
                            {scan.findings_count || 0} issues
                          </span>
                        ) : (
                          <span style={{ color: 'var(--color-text-muted)' }}>—</span>
                        )}
                      </td>
                      <td style={{ color: 'var(--color-text-secondary)', fontSize: '0.8125rem' }}>
                        {scan.created_at ? new Date(scan.created_at).toLocaleString() : '—'}
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end' }}>
                          <Link
                            to={`/scan/${scan.scan_id}`}
                            className="btn btn-outline"
                            style={{ padding: '0.35rem 0.75rem', fontSize: '0.75rem', gap: '4px' }}
                          >
                            View Report <ExternalLink size={12} />
                          </Link>
                          <button
                            type="button"
                            onClick={() => handleScanAgain(scan.target_url)}
                            className="btn btn-outline"
                            style={{ padding: '0.35rem 0.75rem', fontSize: '0.75rem', gap: '4px' }}
                            title="Scan again"
                          >
                            <RotateCcw size={12} /> Scan Again
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default History;

