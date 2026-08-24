// VulnScan Lite — Full Diagnostic Security Report Page

import React, { useState } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import {
  ArrowLeft,
  Download,
  Globe,
  FileText,
  CheckCircle2,
  Wrench,
  RotateCcw,
} from 'lucide-react';
import { useScanPolling } from '../hooks/useScanPolling';
import { downloadPDFReport } from '../services/reportService';
import { ScoreGauge } from '../components/ScoreGauge';
import { ScoreSummary } from '../components/ScoreSummary';
import { SecurityConfigTable } from '../components/SecurityConfigTable';
import { FindingCard } from '../components/FindingCard';
import { RemediationCard } from '../components/RemediationCard';
import { SSLSection } from '../components/SSLSection';
import { TechnologySection } from '../components/TechnologySection';
import { InsecureHttpSection } from '../components/InsecureHttpSection';
import { ScanLimitations } from '../components/ScanLimitations';
import { ReportNav } from '../components/ReportNav';
import { ScanProgress } from '../components/ScanProgress';
import { SecurityDisclaimer } from '../components/SecurityDisclaimer';

export const ScanResult: React.FC = () => {
  const { scanId, id } = useParams<{ scanId?: string; id?: string }>();
  const activeId = scanId || id;
  const navigate = useNavigate();

  const { result, status, stage, stageMessage, loading, error, refetch } = useScanPolling(activeId);
  const [downloading, setDownloading] = useState(false);
  const [downloadError, setDownloadError] = useState<string | null>(null);

  const handleDownloadPDF = async () => {
    if (!activeId) return;
    setDownloadError(null);
    setDownloading(true);

    try {
      await downloadPDFReport(activeId);
    } catch (err: any) {
      setDownloadError(err.message || 'Failed to download PDF report.');
    } finally {
      setDownloading(false);
    }
  };

  const handleScanAgain = () => {
    if (result?.target_url) {
      navigate('/scan', { state: { initialUrl: result.target_url } });
    } else {
      navigate('/scan');
    }
  };

  // If loading or scan is actively queued/running
  if (loading || status === 'queued' || status === 'running') {
    return (
      <div style={{ maxWidth: '800px', margin: '0 auto', display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
        <Link
          to="/dashboard"
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '0.5rem',
            color: 'var(--color-text-secondary)',
            fontSize: '0.875rem',
          }}
        >
          <ArrowLeft size={16} /> Back to Dashboard
        </Link>
        <ScanProgress
          status={status || 'queued'}
          stage={stage}
          stageMessage={stageMessage}
          targetUrl={result?.target_url || 'Target Website'}
          scanId={activeId || ''}
        />
      </div>
    );
  }

  // If scan failed or global error
  if (error || status === 'failed') {
    return (
      <div style={{ maxWidth: '800px', margin: '0 auto', display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
        <Link
          to="/dashboard"
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '0.5rem',
            color: 'var(--color-text-secondary)',
            fontSize: '0.875rem',
          }}
        >
          <ArrowLeft size={16} /> Back to Dashboard
        </Link>
        <ScanProgress
          status="failed"
          stage="failed"
          targetUrl={result?.target_url || 'Target Website'}
          scanId={activeId || ''}
          error={error || result?.error}
          onRetry={refetch}
        />
      </div>
    );
  }

  if (!result) return null;

  const findings = result.findings || [];
  const isHttps = result.target_url.toLowerCase().startsWith('https://');
  const insecureLinks = result.html_data?.insecure_http_links || [];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
      {/* Top Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <Link
            to="/dashboard"
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.5rem',
              color: 'var(--color-text-secondary)',
              marginBottom: '0.75rem',
              fontSize: '0.875rem',
            }}
          >
            <ArrowLeft size={16} /> Back to Dashboard
          </Link>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
            <span style={{ fontSize: '0.8125rem', color: 'var(--color-accent)', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 700 }}>
              Passive Security Report
            </span>
          </div>

          <h1
            style={{
              fontSize: '2.25rem',
              fontWeight: 800,
              display: 'flex',
              alignItems: 'center',
              gap: '0.75rem',
              wordBreak: 'break-all',
              margin: 0,
            }}
          >
            <Globe size={32} color="var(--color-primary)" style={{ flexShrink: 0 }} />
            {result.target_url}
          </h1>

          <div style={{ color: 'var(--color-text-muted)', fontSize: '0.875rem', marginTop: '0.35rem', display: 'flex', alignItems: 'center', gap: '0.6rem', flexWrap: 'wrap' }}>
            <span>Scan ID: <code style={{ fontFamily: 'var(--font-mono)' }}>{result.scan_id}</code></span>
            <span>&bull; Completed {new Date(result.completed_at || result.created_at).toLocaleString()}</span>
            {result.authorization_type && (
              <span className="badge badge-success" style={{ fontSize: '0.75rem', textTransform: 'capitalize', display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                ✓ {result.authorization_type.replace('_', ' ')}
              </span>
            )}
            {result.consent_audit?.consent_version && (
              <span className="badge" style={{ fontSize: '0.75rem', background: 'rgba(99, 102, 241, 0.15)', color: 'var(--color-accent)' }}>
                {result.consent_audit.consent_version}
              </span>
            )}
          </div>
        </div>

        {/* Action Buttons: PDF Download & Scan Again */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
          <button
            type="button"
            onClick={handleScanAgain}
            className="btn btn-outline"
            style={{ padding: '0.625rem 1.25rem' }}
          >
            <RotateCcw size={16} /> Scan Again
          </button>

          <button
            type="button"
            onClick={handleDownloadPDF}
            className="btn btn-primary"
            disabled={downloading}
            style={{ padding: '0.625rem 1.25rem' }}
          >
            {downloading ? (
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <div className="spinner" style={{ width: '16px', height: '16px', borderWidth: '2px' }} />
                <span>Generating PDF...</span>
              </div>
            ) : (
              <>
                <Download size={18} /> Download PDF Report
              </>
            )}
          </button>
          {downloadError && (
            <span className="error-text" style={{ fontSize: '0.8125rem', width: '100%', textAlign: 'right' }}>
              {downloadError}
            </span>
          )}
        </div>
      </div>

      {/* Single Ethical Scanning Notice at Top */}
      <SecurityDisclaimer />

      {/* Sticky In-Page Navigation */}
      <ReportNav
        hasFindings={findings.length > 0}
        hasInsecureHttp={insecureLinks.length > 0}
      />

      {/* 1. Executive Summary */}
      <section id="executive-summary" style={{ scrollMarginTop: '130px', display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '1.5rem' }}>
          <div className="card" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
            <ScoreGauge score={result.score || 0} grade={result.grade} />
          </div>

          <ScoreSummary
            score={result.score}
            grade={result.grade}
            riskLevel={result.risk_level}
            targetUrl={result.target_url}
            scanId={result.scan_id}
            status={result.status}
            createdAt={result.created_at}
            startedAt={result.started_at}
            completedAt={result.completed_at}
            durationSeconds={result.duration_seconds}
            findings={findings}
          />
        </div>
      </section>

      {/* 2. Actionable Security Findings */}
      <section id="findings" style={{ scrollMarginTop: '130px' }}>
        <div className="section-title" style={{ marginBottom: '1rem' }}>
          <FileText size={20} color="var(--color-danger)" />
          <span>Security &amp; Misconfiguration Findings ({findings.length})</span>
        </div>

        {findings.length === 0 ? (
          <div className="card" style={{ textAlign: 'center', padding: '3rem 1rem', color: 'var(--color-text-muted)' }}>
            <CheckCircle2 size={40} color="var(--color-success)" style={{ margin: '0 auto 0.75rem' }} />
            <h3 style={{ fontSize: '1.125rem', fontWeight: 600, color: 'var(--color-text)' }}>
              No security findings detected
            </h3>
            <p style={{ fontSize: '0.875rem', marginTop: '0.25rem' }}>
              No security findings detected by the implemented passive checks. This indicates that baseline passive checks passed, but does not guarantee the absence of all vulnerabilities.
            </p>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            {findings.map((finding) => (
              <FindingCard key={finding.id} finding={finding} />
            ))}
          </div>
        )}
      </section>

      {/* Remediation Guide (if findings exist) */}
      {findings.length > 0 && (
        <section style={{ scrollMarginTop: '130px' }}>
          <div className="section-title" style={{ marginBottom: '1rem' }}>
            <Wrench size={20} color="var(--color-accent)" />
            <span>Remediation &amp; Server Configuration Guide</span>
          </div>
          <RemediationCard findings={findings} />
        </section>
      )}

      {/* 3. Combined Security Configuration & HTTP Headers Table */}
      <section id="security-headers" style={{ scrollMarginTop: '130px' }}>
        <SecurityConfigTable
          checks={result.security_checks || []}
          headerChecks={result.header_data?.checks || []}
          findings={findings}
        />
      </section>

      {/* 4. SSL / TLS Cryptographic Inspection */}
      <section id="tls-https" style={{ scrollMarginTop: '130px' }}>
        <SSLSection ssl={result.ssl_data} />
      </section>

      {/* 5. Technology Information */}
      <section id="technology-info" style={{ scrollMarginTop: '130px' }}>
        <TechnologySection
          headerData={result.header_data}
          cms={result.cms_data}
          htmlData={result.html_data}
        />
      </section>

      {/* 6. Insecure HTTP References */}
      <section id="insecure-http" style={{ scrollMarginTop: '130px' }}>
        <InsecureHttpSection
          insecureHttpLinks={insecureLinks}
          isHttps={isHttps}
        />
      </section>

      {/* 7. Scan Limitations */}
      <section id="limitations" style={{ scrollMarginTop: '130px' }}>
        <ScanLimitations />
      </section>
    </div>
  );
};

export default ScanResult;
