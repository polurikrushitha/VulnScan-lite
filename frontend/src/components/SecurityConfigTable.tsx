// VulnScan Lite — Combined Security Configuration & HTTP Headers Table

import React, { useState } from 'react';
import {
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Info,
  ChevronDown,
  ChevronRight,
  ShieldCheck,
  HelpCircle,
  AlertOctagon,
  Terminal,
  Filter,
} from 'lucide-react';
import type { SecurityCheck, HeaderCheck, Finding, CheckStatus, FindingSeverity } from '../types';

interface SecurityConfigTableProps {
  checks: SecurityCheck[];
  headerChecks?: HeaderCheck[];
  findings?: Finding[];
}

interface MergedCheckItem {
  id: string;
  name: string;
  category: string;
  status: CheckStatus;
  points: number;
  severity?: FindingSeverity;
  confidence: string;
  evidence: string;
  whyItMatters: string;
  impact: string;
  remediation: string;
}

const CHECK_EXPLANATIONS: Record<string, { whyItMatters: string; impact: string; remediation: string }> = {
  'Content-Security-Policy': {
    whyItMatters: 'CSP defines which domains are trusted for executable scripts, stylesheets, and images.',
    impact: 'Without CSP, malicious scripts injected via Cross-Site Scripting (XSS) can execute unrestrained in visitors\' browsers.',
    remediation: 'Configure a Content-Security-Policy HTTP header on your web server with strict source directives (e.g. default-src \'self\').',
  },
  'Strict-Transport-Security': {
    whyItMatters: 'HSTS enforces TLS connections for all future visits and prevents insecure HTTP fallbacks.',
    impact: 'Without HSTS, attackers on the same network can execute SSL stripping or man-in-the-middle downgrade attacks on first-time visitors.',
    remediation: 'Add Strict-Transport-Security: max-age=31536000; includeSubDomains to your HTTPS server responses.',
  },
  'X-Frame-Options': {
    whyItMatters: 'X-Frame-Options informs browsers whether the page can be loaded inside <iframe> elements.',
    impact: 'Without frame restrictions, attackers can embed your website in an invisible iframe to execute clickjacking attacks.',
    remediation: 'Add X-Frame-Options: SAMEORIGIN or use the CSP frame-ancestors directive.',
  },
  'X-Content-Type-Options': {
    whyItMatters: 'nosniff prevents legacy browser MIME-sniffing away from the declared Content-Type.',
    impact: 'Without this header, user-uploaded text or image files might be interpreted as executable HTML/JavaScript.',
    remediation: 'Add X-Content-Type-Options: nosniff to all HTTP responses.',
  },
  'Referrer-Policy': {
    whyItMatters: 'Referrer-Policy restricts the transmission of sensitive URLs in the HTTP Referer header.',
    impact: 'Without a policy, sensitive URL parameters (tokens, IDs) may leak to external third-party servers.',
    remediation: 'Set Referrer-Policy: strict-origin-when-cross-origin.',
  },
  'Permissions-Policy': {
    whyItMatters: 'Permissions-Policy restricts access to sensitive browser features (camera, microphone, geolocation).',
    impact: 'Unrestricted browser capabilities remain accessible to embedded third-party scripts and ads.',
    remediation: 'Add Permissions-Policy: camera=(), microphone=(), geolocation=() to restrict unused browser APIs.',
  },
  'SSL/TLS Certificate': {
    whyItMatters: 'TLS certificates encrypt traffic between visitors and your web server.',
    impact: 'Expired or invalid certificates trigger browser security warnings and leave communication unencrypted.',
    remediation: 'Renew and install a valid certificate issued by a trusted Certificate Authority (e.g. Let\'s Encrypt).',
  },
  'Insecure HTTP References': {
    whyItMatters: 'All resources on an HTTPS webpage should be loaded securely over HTTPS.',
    impact: 'Loading HTTP assets on an HTTPS page may create mixed-content security warnings or transport vulnerabilities.',
    remediation: 'Update all image, script, stylesheet, and iframe URLs to use HTTPS.',
  },
};

export const SecurityConfigTable: React.FC<SecurityConfigTableProps> = ({
  checks,
  headerChecks = [],
  findings = [],
}) => {
  const [filter, setFilter] = useState<'all' | 'issues' | 'passed'>('all');
  const [expandedRows, setExpandedRows] = useState<Set<string>>(new Set());

  // Merge and deduplicate checks
  const mergedItems: MergedCheckItem[] = [];
  const seenNames = new Set<string>();

  // 1. Process structured checks
  checks.forEach((chk) => {
    const key = chk.check_name.toLowerCase().trim();
    if (seenNames.has(key)) return;
    seenNames.add(key);

    const matchedFinding = findings.find(
      (f) =>
        f.check_name.toLowerCase().includes(key) ||
        key.includes(f.check_name.toLowerCase())
    );

    const defaultInfo = CHECK_EXPLANATIONS[chk.check_name] || {
      whyItMatters: chk.description || 'Validates baseline security configuration.',
      impact: matchedFinding?.impact || 'Potential exposure to security misconfigurations.',
      remediation: matchedFinding?.remediation || 'Follow vendor documentation to apply defensive hardening.',
    };

    let severity: FindingSeverity | undefined = matchedFinding?.severity;
    if (!severity && chk.status === 'failed') {
      severity = chk.points <= -10 ? 'high' : 'medium';
    } else if (!severity && chk.status === 'warning') {
      severity = 'low';
    }

    const conf = matchedFinding?.confidence ? matchedFinding.confidence.toLowerCase() : 'high';
    const normalizedConf = conf === 'high' ? 'High' : conf === 'medium' ? 'Medium' : 'Low';

    mergedItems.push({
      id: chk.id || chk.check_name,
      name: chk.check_name,
      category: chk.category || 'Security',
      status: chk.status,
      points: chk.points,
      severity,
      confidence: normalizedConf,
      evidence: matchedFinding?.evidence || chk.description || 'Observed standard configuration',
      whyItMatters: defaultInfo.whyItMatters,
      impact: matchedFinding?.impact || defaultInfo.impact,
      remediation: matchedFinding?.remediation || defaultInfo.remediation,
    });
  });

  // 2. Process any header checks not yet merged
  headerChecks.forEach((hc) => {
    const key = hc.header_name.toLowerCase().trim();
    if (seenNames.has(key)) return;
    seenNames.add(key);

    const matchedFinding = findings.find(
      (f) =>
        f.check_name.toLowerCase().includes(key) ||
        key.includes(f.check_name.toLowerCase())
    );

    const defaultInfo = CHECK_EXPLANATIONS[hc.header_name] || {
      whyItMatters: hc.description,
      impact: matchedFinding?.impact || 'Missing defense-in-depth protection in browser environments.',
      remediation: matchedFinding?.remediation || hc.remediation,
    };

    const status: CheckStatus = hc.present ? 'passed' : hc.points < 0 ? 'failed' : 'info';
    const severity: FindingSeverity | undefined = !hc.present && hc.points < 0 ? (hc.points <= -10 ? 'high' : 'low') : undefined;

    mergedItems.push({
      id: hc.header_name,
      name: hc.header_name,
      category: hc.category || 'Headers',
      status,
      points: hc.points,
      severity,
      confidence: 'High',
      evidence: hc.value ? `Header present: ${hc.value}` : 'Header absent from HTTP response',
      whyItMatters: defaultInfo.whyItMatters,
      impact: matchedFinding?.impact || defaultInfo.impact,
      remediation: matchedFinding?.remediation || hc.remediation || defaultInfo.remediation,
    });
  });

  const passedCount = mergedItems.filter((i) => i.status === 'passed').length;
  const issuesCount = mergedItems.filter((i) => i.status === 'failed' || i.status === 'warning').length;

  const filteredItems = mergedItems.filter((item) => {
    if (filter === 'passed') return item.status === 'passed';
    if (filter === 'issues') return item.status === 'failed' || item.status === 'warning';
    return true;
  });

  const toggleRow = (id: string) => {
    setExpandedRows((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  const getStatusBadge = (status: CheckStatus) => {
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

  const getSeverityBadge = (severity?: FindingSeverity) => {
    if (!severity) return <span style={{ color: 'var(--color-text-muted)' }}>—</span>;
    const colors: Record<string, string> = {
      critical: 'var(--color-danger)',
      high: '#ea580c',
      medium: 'var(--color-warning)',
      low: 'var(--color-info)',
      info: 'var(--color-text-secondary)',
    };
    const c = colors[severity] || 'var(--color-text-muted)';
    return (
      <span
        className="badge"
        style={{
          background: `${c}15`,
          color: c,
          border: `1px solid ${c}35`,
          textTransform: 'uppercase',
          fontSize: '0.6875rem',
          fontWeight: 700,
        }}
      >
        {severity}
      </span>
    );
  };

  return (
    <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
      {/* Header Controls */}
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
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <ShieldCheck size={20} color="var(--color-primary)" />
            <h3 style={{ fontSize: '1.125rem', fontWeight: 700, color: 'var(--color-text)', margin: 0 }}>
              Security Configuration &amp; HTTP Headers
            </h3>
          </div>
          <p style={{ fontSize: '0.8125rem', color: 'var(--color-text-muted)', marginTop: '0.25rem' }}>
            {passedCount} passed &bull; {issuesCount} issue(s) detected across {mergedItems.length} total checks. Click any row to expand details.
          </p>
        </div>

        {/* Filter Buttons */}
        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
          <Filter size={14} color="var(--color-text-muted)" />
          <button
            type="button"
            className={`btn ${filter === 'all' ? 'btn-primary' : 'btn-outline'}`}
            style={{ padding: '0.35rem 0.75rem', fontSize: '0.75rem' }}
            onClick={() => setFilter('all')}
          >
            All ({mergedItems.length})
          </button>
          <button
            type="button"
            className={`btn ${filter === 'issues' ? 'btn-primary' : 'btn-outline'}`}
            style={{ padding: '0.35rem 0.75rem', fontSize: '0.75rem' }}
            onClick={() => setFilter('issues')}
          >
            Issues ({issuesCount})
          </button>
          <button
            type="button"
            className={`btn ${filter === 'passed' ? 'btn-primary' : 'btn-outline'}`}
            style={{ padding: '0.35rem 0.75rem', fontSize: '0.75rem' }}
            onClick={() => setFilter('passed')}
          >
            Passed ({passedCount})
          </button>
        </div>
      </div>

      {/* Table */}
      {filteredItems.length === 0 ? (
        <div style={{ padding: '3rem 1.5rem', textAlign: 'center', color: 'var(--color-text-muted)' }}>
          No security checks matching the selected filter.
        </div>
      ) : (
        <div style={{ overflowX: 'auto' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th style={{ width: '36px' }}></th>
                <th style={{ minWidth: '200px' }}>Check</th>
                <th>Category</th>
                <th>Status</th>
                <th>Severity</th>
                <th>Confidence</th>
                <th style={{ minWidth: '220px' }}>Evidence / Detail</th>
              </tr>
            </thead>
            <tbody>
              {filteredItems.map((item) => {
                const isExpanded = expandedRows.has(item.id);
                return (
                  <React.Fragment key={item.id}>
                    <tr
                      onClick={() => toggleRow(item.id)}
                      style={{
                        cursor: 'pointer',
                        background: isExpanded ? 'rgba(99, 102, 241, 0.05)' : undefined,
                      }}
                    >
                      <td style={{ textAlign: 'center', color: 'var(--color-text-muted)' }}>
                        {isExpanded ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                      </td>
                      <td style={{ fontWeight: 600, color: 'var(--color-text)' }}>
                        {item.name}
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
                          {item.category}
                        </span>
                      </td>
                      <td>{getStatusBadge(item.status)}</td>
                      <td>{getSeverityBadge(item.severity)}</td>
                      <td>
                        <span
                          className="badge"
                          style={{
                            background: 'var(--color-bg-secondary)',
                            color: 'var(--color-text-secondary)',
                            border: '1px solid var(--color-border)',
                            fontSize: '0.6875rem',
                          }}
                        >
                          {item.confidence}
                        </span>
                      </td>
                      <td style={{ fontSize: '0.8125rem', color: 'var(--color-text-secondary)' }}>
                        <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem' }}>
                          {item.evidence.length > 50 ? `${item.evidence.substring(0, 50)}...` : item.evidence}
                        </span>
                      </td>
                    </tr>

                    {/* Expandable Details Drawer */}
                    {isExpanded && (
                      <tr style={{ background: 'rgba(15, 23, 42, 0.5)' }}>
                        <td colSpan={7} style={{ padding: '1rem 1.5rem' }}>
                          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem' }}>
                            {/* Why it matters */}
                            <div
                              style={{
                                background: 'var(--color-bg-secondary)',
                                padding: '0.875rem',
                                borderRadius: 'var(--radius-sm)',
                                border: '1px solid var(--color-border)',
                              }}
                            >
                              <div style={{ display: 'flex', alignItems: 'center', gap: '4px', fontWeight: 600, color: 'var(--color-text)', fontSize: '0.8125rem', marginBottom: '0.375rem' }}>
                                <HelpCircle size={14} color="var(--color-accent)" /> Why it matters:
                              </div>
                              <p style={{ margin: 0, fontSize: '0.8125rem', color: 'var(--color-text-secondary)', lineHeight: 1.5 }}>
                                {item.whyItMatters}
                              </p>
                            </div>

                            {/* Security Impact */}
                            <div
                              style={{
                                background: 'var(--color-bg-secondary)',
                                padding: '0.875rem',
                                borderRadius: 'var(--radius-sm)',
                                border: '1px solid var(--color-border)',
                              }}
                            >
                              <div style={{ display: 'flex', alignItems: 'center', gap: '4px', fontWeight: 600, color: 'var(--color-text)', fontSize: '0.8125rem', marginBottom: '0.375rem' }}>
                                <AlertOctagon size={14} color="var(--color-warning)" /> Security Impact:
                              </div>
                              <p style={{ margin: 0, fontSize: '0.8125rem', color: 'var(--color-text-secondary)', lineHeight: 1.5 }}>
                                {item.impact}
                              </p>
                            </div>

                            {/* Full Evidence */}
                            <div
                              style={{
                                background: 'var(--color-bg-secondary)',
                                padding: '0.875rem',
                                borderRadius: 'var(--radius-sm)',
                                border: '1px solid var(--color-border)',
                              }}
                            >
                              <div style={{ display: 'flex', alignItems: 'center', gap: '4px', fontWeight: 600, color: 'var(--color-text)', fontSize: '0.8125rem', marginBottom: '0.375rem' }}>
                                <Terminal size={14} color="var(--color-info)" /> Observed Evidence:
                              </div>
                              <div style={{ margin: 0, fontSize: '0.75rem', color: 'var(--color-text)', fontFamily: 'var(--font-mono)', wordBreak: 'break-all' }}>
                                {item.evidence}
                              </div>
                            </div>

                            {/* Recommended Remediation */}
                            <div
                              style={{
                                background: 'rgba(99, 102, 241, 0.06)',
                                padding: '0.875rem',
                                borderRadius: 'var(--radius-sm)',
                                border: '1px solid rgba(99, 102, 241, 0.25)',
                              }}
                            >
                              <div style={{ display: 'flex', alignItems: 'center', gap: '4px', fontWeight: 600, color: 'var(--color-accent)', fontSize: '0.8125rem', marginBottom: '0.375rem' }}>
                                <Terminal size={14} /> Recommended Remediation:
                              </div>
                              <pre style={{ margin: 0, fontSize: '0.75rem', color: 'var(--color-text)', fontFamily: 'var(--font-mono)', whiteSpace: 'pre-wrap' }}>
                                {item.remediation}
                              </pre>
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

export default SecurityConfigTable;
