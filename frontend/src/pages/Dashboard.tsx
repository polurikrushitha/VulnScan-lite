// VulnScan Lite — User Security Dashboard

import React, { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Shield, PlusCircle, Clock, Search, AlertCircle, ArrowRight, CheckCircle2, XCircle, AlertTriangle, ExternalLink, RotateCcw } from 'lucide-react';
import { getScanHistory, createScan } from '../services/scanService';
import { getMe } from '../services/authService';
import type { ScanHistoryItem, User } from '../types';
import { formatApiError } from '../services/api';
import { SecurityDisclaimer } from '../components/SecurityDisclaimer';
import { ConsentModal } from '../components/ConsentModal';

export const Dashboard: React.FC = () => {
  const navigate = useNavigate();
  const [history, setHistory] = useState<ScanHistoryItem[]>([]);
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string>('');

  const [url, setUrl] = useState<string>('');
  const [scanLoading, setScanLoading] = useState<boolean>(false);
  const [scanError, setScanError] = useState<string>('');

  useEffect(() => {
    let isMounted = true;

    const loadDashboardData = async () => {
      try {
        setLoading(true);
        setError('');
        const [historyRes, userRes] = await Promise.allSettled([
          getScanHistory(),
          getMe(),
        ]);

        if (!isMounted) return;

        if (historyRes.status === 'fulfilled' && Array.isArray(historyRes.value)) {
          setHistory(historyRes.value);
        } else if (historyRes.status === 'rejected') {
          setError(formatApiError(historyRes.reason));
        }

        if (userRes.status === 'fulfilled') {
          setUser(userRes.value);
        } else if (userRes.status === 'rejected') {
          setError(formatApiError(userRes.reason));
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

    loadDashboardData();

    return () => {
      isMounted = false;
    };
  }, []);

  const [isConsentOpen, setIsConsentOpen] = useState<boolean>(false);

  const handleStartScan = (e: React.FormEvent) => {
    e.preventDefault();
    setScanError('');

    const trimmed = url.trim();
    if (!trimmed.startsWith('http://') && !trimmed.startsWith('https://')) {
      setScanError('Please provide a valid URL beginning with http:// or https://');
      return;
    }

    setIsConsentOpen(true);
  };

  const handleConsentConfirmed = async (payload: any) => {
    setScanLoading(true);
    setScanError('');

    try {
      const data = await createScan(payload);
      setIsConsentOpen(false);
      navigate(`/scan/${data.scan_id}`);
    } catch (err: any) {
      setScanError(formatApiError(err));
      setIsConsentOpen(false);
    } finally {
      setScanLoading(false);
    }
  };

  const handleScanAgain = (targetUrl: string) => {
    navigate('/scan', { state: { initialUrl: targetUrl } });
  };

  // Safe array & stats calculation
  const safeHistory = Array.isArray(history) ? history : [];
  const totalScans = safeHistory.length;
  const completedScans = safeHistory.filter((s) => s?.status === 'completed').length;
  const failedScans = safeHistory.filter((s) => s?.status === 'failed').length;
  const totalFindings = safeHistory.reduce((sum, s) => sum + (s.findings_count || 0), 0);

  const displayName = user?.name || user?.email?.split('@')[0] || 'User';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
      {/* Header & Greeting */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h1 style={{ fontSize: '2rem', fontWeight: 800, color: 'var(--color-text)' }}>
            Welcome back, <span className="gradient-text">{displayName}</span>
          </h1>
          <p style={{ color: 'var(--color-text-secondary)', fontSize: '0.9375rem', marginTop: '0.25rem' }}>
            {user?.email ? `Account: ${user.email}` : 'Monitor your web targets and configuration audit history'}
          </p>
        </div>

        <Link to="/scan" className="btn btn-primary" style={{ padding: '0.625rem 1.25rem', fontSize: '0.9375rem' }}>
          <PlusCircle size={18} /> New Scan
        </Link>
      </div>

      <SecurityDisclaimer />

      {/* Summary Cards: 4 Key Metrics */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '1.25rem' }}>
        {/* Total Scans */}
        <div className="card" style={{ display: 'flex', alignItems: 'center', gap: '1rem', padding: '1.25rem' }}>
          <div
            style={{
              width: '48px',
              height: '48px',
              borderRadius: '12px',
              background: 'rgba(99, 102, 241, 0.15)',
              border: '1px solid rgba(99, 102, 241, 0.3)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              flexShrink: 0,
            }}
          >
            <Shield size={24} color="var(--color-primary)" />
          </div>
          <div>
            <div style={{ fontSize: '0.8125rem', color: 'var(--color-text-secondary)', fontWeight: 600, textTransform: 'uppercase' }}>
              Total Scans
            </div>
            <div style={{ fontSize: '1.75rem', fontWeight: 800, color: 'var(--color-text)', marginTop: '0.125rem' }}>
              {loading ? '—' : totalScans}
            </div>
          </div>
        </div>

        {/* Completed Scans */}
        <div className="card" style={{ display: 'flex', alignItems: 'center', gap: '1rem', padding: '1.25rem' }}>
          <div
            style={{
              width: '48px',
              height: '48px',
              borderRadius: '12px',
              background: 'rgba(34, 197, 94, 0.15)',
              border: '1px solid rgba(34, 197, 94, 0.3)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              flexShrink: 0,
            }}
          >
            <CheckCircle2 size={24} color="var(--color-success)" />
          </div>
          <div>
            <div style={{ fontSize: '0.8125rem', color: 'var(--color-text-secondary)', fontWeight: 600, textTransform: 'uppercase' }}>
              Completed Scans
            </div>
            <div style={{ fontSize: '1.75rem', fontWeight: 800, color: 'var(--color-success)', marginTop: '0.125rem' }}>
              {loading ? '—' : completedScans}
            </div>
          </div>
        </div>

        {/* Failed Scans */}
        <div className="card" style={{ display: 'flex', alignItems: 'center', gap: '1rem', padding: '1.25rem' }}>
          <div
            style={{
              width: '48px',
              height: '48px',
              borderRadius: '12px',
              background: 'rgba(239, 68, 68, 0.15)',
              border: '1px solid rgba(239, 68, 68, 0.3)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              flexShrink: 0,
            }}
          >
            <XCircle size={24} color="var(--color-danger)" />
          </div>
          <div>
            <div style={{ fontSize: '0.8125rem', color: 'var(--color-text-secondary)', fontWeight: 600, textTransform: 'uppercase' }}>
              Failed Scans
            </div>
            <div style={{ fontSize: '1.75rem', fontWeight: 800, color: 'var(--color-danger)', marginTop: '0.125rem' }}>
              {loading ? '—' : failedScans}
            </div>
          </div>
        </div>

        {/* Vulnerabilities Found */}
        <div className="card" style={{ display: 'flex', alignItems: 'center', gap: '1rem', padding: '1.25rem' }}>
          <div
            style={{
              width: '48px',
              height: '48px',
              borderRadius: '12px',
              background: 'rgba(245, 158, 11, 0.15)',
              border: '1px solid rgba(245, 158, 11, 0.3)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              flexShrink: 0,
            }}
          >
            <AlertTriangle size={24} color="var(--color-warning)" />
          </div>
          <div>
            <div style={{ fontSize: '0.8125rem', color: 'var(--color-text-secondary)', fontWeight: 600, textTransform: 'uppercase' }}>
              Vulnerabilities Found
            </div>
            <div style={{ fontSize: '1.75rem', fontWeight: 800, color: 'var(--color-warning)', marginTop: '0.125rem' }}>
              {loading ? '—' : totalFindings}
            </div>
          </div>
        </div>
      </div>

      {/* Quick On-Demand Scan Input */}
      <div className="card" style={{ background: 'linear-gradient(135deg, rgba(99, 102, 241, 0.08), rgba(15, 23, 42, 0.6))' }}>
        <h2 style={{ fontSize: '1.125rem', fontWeight: 700, marginBottom: '0.5rem' }}>
          Initiate New On-Demand Scan
        </h2>
        <p style={{ fontSize: '0.875rem', color: 'var(--color-text-secondary)', marginBottom: '1.25rem' }}>
          Enter an authorized domain or URL to launch an asynchronous passive security scan.
        </p>

        <form onSubmit={handleStartScan} style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
          <div style={{ position: 'relative', flex: 1, minWidth: '260px' }}>
            <Search size={18} style={{ position: 'absolute', left: '1rem', top: '50%', transform: 'translateY(-50%)', color: 'var(--color-text-muted)' }} />
            <input
              type="url"
              className="form-input"
              placeholder="https://example.com"
              style={{ paddingLeft: '2.75rem' }}
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              disabled={scanLoading}
              required
            />
          </div>
          <button type="submit" className="btn btn-primary" disabled={scanLoading || !url.trim()} style={{ whiteSpace: 'nowrap' }}>
            {scanLoading ? (
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <div className="spinner" style={{ width: '16px', height: '16px', borderWidth: '2px' }} />
                <span>Launching...</span>
              </div>
            ) : (
              <>
                <Search size={16} /> Scan Target
              </>
            )}
          </button>
        </form>
        {scanError && <div className="error-text" style={{ marginTop: '0.75rem' }}>{scanError}</div>}
      </div>

      {/* Recent Scans Table */}
      <div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
          <h3 className="section-title" style={{ margin: 0 }}>
            <Clock size={20} /> Recent Scans
          </h3>
          {safeHistory.length > 5 && (
            <Link to="/history" style={{ fontSize: '0.875rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '4px' }}>
              View all history <ArrowRight size={14} />
            </Link>
          )}
        </div>

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
            <h4 style={{ fontSize: '1.125rem', fontWeight: 700, marginBottom: '0.5rem' }}>No scans yet</h4>
            <p style={{ color: 'var(--color-text-secondary)', marginBottom: '1.5rem' }}>
              Start your first passive security scan to analyze SSL, headers, and CMS posture.
            </p>
            <Link to="/scan" className="btn btn-primary">
              <PlusCircle size={18} /> Start your first scan
            </Link>
          </div>
        ) : (
          <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
            <div style={{ overflowX: 'auto' }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th style={{ minWidth: '220px' }}>Target URL</th>
                    <th>Status</th>
                    <th>Score &amp; Risk Level</th>
                    <th>Findings</th>
                    <th>Date &amp; Time</th>
                    <th style={{ textAlign: 'right' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {safeHistory.slice(0, 5).map((scan) => {
                    const risk = scan.risk_level || (scan.score !== undefined && scan.score !== null ? (scan.score >= 90 ? 'Excellent' : scan.score >= 80 ? 'Good' : scan.score >= 65 ? 'Moderate' : scan.score >= 50 ? 'Needs Improvement' : 'Poor') : undefined);
                    return (
                      <tr key={scan.scan_id}>
                        <td style={{ fontWeight: 600, color: 'var(--color-text)' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                            <span style={{ wordBreak: 'break-all' }}>{scan.target_url}</span>
                          </div>
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
                          {scan.status === 'completed' && scan.score !== undefined && scan.score !== null ? (
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                              <strong>{scan.score.toFixed(1)}</strong>
                              {risk && (
                                <span
                                  className="badge"
                                  style={{
                                    fontSize: '0.6875rem',
                                    background: 'var(--color-bg-secondary)',
                                    border: '1px solid var(--color-border)',
                                    color: 'var(--color-text-secondary)',
                                  }}
                                >
                                  {risk}
                                </span>
                              )}
                            </div>
                          ) : (
                            <span style={{ color: 'var(--color-text-muted)' }}>—</span>
                          )}
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
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>

      <ConsentModal
        isOpen={isConsentOpen}
        targetUrl={url.trim()}
        onClose={() => setIsConsentOpen(false)}
        onConfirm={handleConsentConfirmed}
        loading={scanLoading}
      />
    </div>
  );
};

export default Dashboard;

