// VulnScan Lite — Dedicated New Scan Page with Authorization & Consent Workflow

import React, { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { Search, ArrowRight, AlertCircle, Info, CheckCircle2, Lock } from 'lucide-react';
import { createScan } from '../services/scanService';
import { formatApiError } from '../services/api';
import { SecurityDisclaimer } from '../components/SecurityDisclaimer';
import { ConsentModal } from '../components/ConsentModal';
import type { ScanCreatePayload } from '../types';

const URL_PATTERN = /^https?:\/\/[a-zA-Z0-9-._~:/?#[\]@!$&'()*+,;=]+$/i;

export const Scan: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const initialUrl = (location.state as { initialUrl?: string })?.initialUrl || '';

  const [url, setUrl] = useState(initialUrl);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [isConsentOpen, setIsConsentOpen] = useState(false);

  const trimmedUrl = url.trim();
  const isUrlFormatValid =
    trimmedUrl.length > 0 &&
    (trimmedUrl.startsWith('http://') || trimmedUrl.startsWith('https://')) &&
    URL_PATTERN.test(trimmedUrl);

  const handleOpenConsent = (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (!isUrlFormatValid) {
      setError('Please enter a valid URL (e.g. https://example.com)');
      return;
    }

    setIsConsentOpen(true);
  };

  const handleConsentConfirmed = async (payload: ScanCreatePayload) => {
    setLoading(true);
    setError('');

    try {
      const response = await createScan(payload);
      setIsConsentOpen(false);
      navigate(`/scan/${response.scan_id}`);
    } catch (err: any) {
      setError(formatApiError(err));
      setIsConsentOpen(false);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ maxWidth: '720px', margin: '0 auto', display: 'flex', flexDirection: 'column', gap: '2rem' }}>
      <div>
        <h1 style={{ fontSize: '2.25rem', fontWeight: 800, color: 'var(--color-text)' }}>
          Start New Security Scan
        </h1>
        <p style={{ color: 'var(--color-text-secondary)', fontSize: '1rem', marginTop: '0.5rem' }}>
          Dispatch an asynchronous passive audit to examine TLS security, HTTP response headers, technology footprints, and HTML metadata.
        </p>
      </div>

      <SecurityDisclaimer />

      <div className="card" style={{ padding: '2rem' }}>
        {error && (
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem',
              color: 'var(--color-danger)',
              background: 'rgba(239, 68, 68, 0.1)',
              border: '1px solid rgba(239, 68, 68, 0.25)',
              padding: '0.75rem 1rem',
              borderRadius: 'var(--radius-md)',
              fontSize: '0.875rem',
              marginBottom: '1.5rem',
            }}
          >
            <AlertCircle size={18} style={{ flexShrink: 0 }} />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleOpenConsent} style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          <div className="form-group">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <label className="form-label" htmlFor="scan-target-url" style={{ margin: 0 }}>
                Target Website URL
              </label>
              {trimmedUrl.length > 0 && (
                <span
                  style={{
                    fontSize: '0.75rem',
                    fontWeight: 600,
                    display: 'flex',
                    alignItems: 'center',
                    gap: '4px',
                    color: isUrlFormatValid ? 'var(--color-success)' : 'var(--color-danger)',
                  }}
                >
                  {isUrlFormatValid ? (
                    <>
                      <CheckCircle2 size={13} /> Valid URL format
                    </>
                  ) : (
                    <>
                      <AlertCircle size={13} /> Invalid URL format
                    </>
                  )}
                </span>
              )}
            </div>

            <div style={{ position: 'relative', marginTop: '0.375rem' }}>
              <Search size={18} style={{ position: 'absolute', left: '1rem', top: '50%', transform: 'translateY(-50%)', color: 'var(--color-text-muted)' }} />
              <input
                id="scan-target-url"
                type="url"
                className="form-input"
                style={{
                  paddingLeft: '2.75rem',
                  borderColor:
                    trimmedUrl.length > 0
                      ? isUrlFormatValid
                        ? 'var(--color-success)'
                        : 'var(--color-danger)'
                      : undefined,
                }}
                placeholder="https://example.com"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                disabled={loading}
                required
                autoFocus
              />
            </div>
            <span style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)', marginTop: '0.25rem' }}>
              Enter full URL including protocol (e.g., https://example.com or http://localhost:3000)
            </span>
          </div>

          <div
            style={{
              background: 'var(--color-bg-secondary)',
              border: '1px solid var(--color-border)',
              borderRadius: 'var(--radius-md)',
              padding: '1rem',
              fontSize: '0.8125rem',
              color: 'var(--color-text-secondary)',
              display: 'flex',
              flexDirection: 'column',
              gap: '0.5rem',
            }}
          >
            <div style={{ fontWeight: 600, color: 'var(--color-text)', display: 'flex', alignItems: 'center', gap: '4px' }}>
              <Info size={14} color="var(--color-accent)" /> Multi-Layer Security &amp; Authorization Workflow:
            </div>
            <ul style={{ paddingLeft: '1.25rem', margin: 0, lineHeight: 1.6 }}>
              <li><strong>Step 1:</strong> Authenticated identity verification &amp; target normalization</li>
              <li><strong>Step 2:</strong> Explicit ownership/permission declaration &amp; 5-point consent confirmation</li>
              <li><strong>Step 3:</strong> Server-side SSRF security policy &amp; DNS validation</li>
              <li><strong>Step 4:</strong> Non-intrusive passive SSL, header, technology, and HTML audit</li>
            </ul>
          </div>

          <button
            type="submit"
            className="btn btn-primary btn-lg"
            disabled={loading || !isUrlFormatValid}
            style={{ justifyContent: 'center' }}
          >
            {loading ? (
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <div className="spinner" style={{ width: '18px', height: '18px', borderWidth: '2px' }} />
                <span>Launching Scan...</span>
              </div>
            ) : (
              <>
                <Lock size={18} /> Proceed to Authorization &amp; Consent <ArrowRight size={18} />
              </>
            )}
          </button>
        </form>
      </div>

      {/* Structured Authorization & Consent Modal */}
      <ConsentModal
        isOpen={isConsentOpen}
        targetUrl={trimmedUrl}
        onClose={() => setIsConsentOpen(false)}
        onConfirm={handleConsentConfirmed}
        loading={loading}
      />
    </div>
  );
};

export default Scan;

