// VulnScan Lite — Landing Page

import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Shield, Search, ArrowRight, Lock, FileText, Server, Eye } from 'lucide-react';
import { isAuthenticated } from '../services/authService';
import { SecurityDisclaimer } from '../components/SecurityDisclaimer';

export const Home: React.FC = () => {
  const navigate = useNavigate();
  const [url, setUrl] = useState('');
  const [error, setError] = useState('');
  const authed = isAuthenticated();

  const handleStartScan = (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    const trimmed = url.trim();
    if (!trimmed) return;

    if (!authed) {
      // Authentication Gate: Guide unauthenticated user to login/register
      navigate('/login', { state: { returnUrl: '/scan', initialUrl: trimmed } });
      return;
    }

    // Authenticated: Route to dedicated scan authorization & consent page
    navigate('/scan', { state: { initialUrl: trimmed } });
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '4rem', paddingBottom: '3rem' }}>
      {/* Hero Section */}
      <section style={{ textAlign: 'center', maxWidth: '840px', margin: '0 auto', paddingTop: '2rem' }}>
        <div
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '0.5rem',
            padding: '0.35rem 0.85rem',
            borderRadius: '20px',
            background: 'rgba(99, 102, 241, 0.12)',
            border: '1px solid rgba(99, 102, 241, 0.3)',
            color: 'var(--color-accent)',
            fontSize: '0.8125rem',
            fontWeight: 600,
            marginBottom: '1.5rem',
          }}
        >
          <Eye size={14} /> On-Demand Web Vulnerability &amp; Health Scanner
        </div>

        <h1 style={{ fontSize: '3rem', fontWeight: 800, lineHeight: 1.15, marginBottom: '1.25rem', letterSpacing: '-0.03em' }}>
          Assess Your Website's Public Security Posture in <span className="gradient-text">Seconds</span>
        </h1>

        <p style={{ color: 'var(--color-text-secondary)', fontSize: '1.1875rem', lineHeight: 1.6, marginBottom: '2.5rem', maxWidth: '680px', margin: '0 auto 2.5rem' }}>
          Perform a passive security health analysis of a website's publicly exposed security configuration, certificates, and headers.
        </p>

        {/* Scan Input Form */}
        <form onSubmit={handleStartScan} className="card" style={{ padding: '0.875rem', maxWidth: '640px', margin: '0 auto', background: 'var(--color-bg-secondary)' }}>
          <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
            <div style={{ position: 'relative', flex: 1, minWidth: '240px' }}>
              <Search size={18} style={{ position: 'absolute', left: '1rem', top: '50%', transform: 'translateY(-50%)', color: 'var(--color-text-muted)' }} />
              <input
                type="url"
                className="form-input"
                placeholder="https://example.com"
                style={{ paddingLeft: '2.75rem' }}
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                required
              />
            </div>
            <button
              type="submit"
              className="btn btn-primary"
              style={{ padding: '0.75rem 1.5rem', whiteSpace: 'nowrap' }}
            >
              Start Scan <ArrowRight size={16} />
            </button>
          </div>
        </form>

        {error && (
          <div className="error-text" style={{ marginTop: '0.75rem', fontSize: '0.875rem' }}>
            {error}
          </div>
        )}

        <div style={{ marginTop: '2rem', maxWidth: '640px', margin: '2rem auto 0' }}>
          <SecurityDisclaimer />
        </div>
      </section>

      {/* Feature Highlights Grid */}
      <section style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '1.5rem' }}>
        <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          <div style={{ width: '42px', height: '42px', borderRadius: '10px', background: 'rgba(99, 102, 241, 0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Shield size={22} color="var(--color-primary)" />
          </div>
          <h3 style={{ fontSize: '1.125rem', fontWeight: 700 }}>100% Passive &amp; Ethical</h3>
          <p style={{ color: 'var(--color-text-secondary)', fontSize: '0.875rem', lineHeight: 1.6 }}>
            Zero intrusive probes, no exploitation payloads, and no denial-of-service tests. Strictly inspects publicly exposed HTTP responses and TLS certificates.
          </p>
        </div>

        <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          <div style={{ width: '42px', height: '42px', borderRadius: '10px', background: 'rgba(34, 211, 238, 0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Lock size={22} color="var(--color-accent)" />
          </div>
          <h3 style={{ fontSize: '1.125rem', fontWeight: 700 }}>SSL/TLS Health Inspection</h3>
          <p style={{ color: 'var(--color-text-secondary)', fontSize: '0.875rem', lineHeight: 1.6 }}>
            Validates cryptographic chain of trust, expiry dates, negotiated TLS protocol versions, and cipher suites with actionable warning thresholds.
          </p>
        </div>

        <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          <div style={{ width: '42px', height: '42px', borderRadius: '10px', background: 'rgba(34, 197, 94, 0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Server size={22} color="var(--color-success)" />
          </div>
          <h3 style={{ fontSize: '1.125rem', fontWeight: 700 }}>Security Headers &amp; CMS</h3>
          <p style={{ color: 'var(--color-text-secondary)', fontSize: '0.875rem', lineHeight: 1.6 }}>
            Evaluates CSP, X-Frame-Options, HSTS, and referrer policies while safely identifying exposed CMS platforms and generator versions.
          </p>
        </div>

        <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          <div style={{ width: '42px', height: '42px', borderRadius: '10px', background: 'rgba(250, 204, 21, 0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <FileText size={22} color="var(--color-warning)" />
          </div>
          <h3 style={{ fontSize: '1.125rem', fontWeight: 700 }}>PDF Audits &amp; Remediation</h3>
          <p style={{ color: 'var(--color-text-secondary)', fontSize: '0.875rem', lineHeight: 1.6 }}>
            Download executive-grade ReportLab PDF summaries and copy ready-to-use Nginx and Apache server configuration snippets for fast remediation.
          </p>
        </div>
      </section>

      {/* CTA Box */}
      {!authed && (
        <section
          className="card"
          style={{
            background: 'linear-gradient(135deg, rgba(99, 102, 241, 0.15), rgba(15, 23, 42, 0.9))',
            textAlign: 'center',
            padding: '3rem 1.5rem',
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            gap: '1.25rem',
          }}
        >
          <h2 style={{ fontSize: '1.875rem', fontWeight: 800 }}>Ready to analyze your web application?</h2>
          <p style={{ color: 'var(--color-text-secondary)', maxWidth: '540px' }}>
            Create an account in seconds to run scans, monitor security grade history, and export executive PDF reports.
          </p>
          <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap', justifyContent: 'center' }}>
            <Link to="/register" className="btn btn-primary btn-lg">
              Get Started Free
            </Link>
            <Link to="/login" className="btn btn-outline btn-lg">
              Sign In
            </Link>
          </div>
        </section>
      )}
    </div>
  );
};

export default Home;
