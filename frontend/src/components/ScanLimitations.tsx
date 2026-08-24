// VulnScan Lite — Dedicated Scan Limitations Section

import React from 'react';
import { AlertCircle, CheckCircle2 } from 'lucide-react';

export const ScanLimitations: React.FC = () => {
  return (
    <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '1rem', borderLeft: '4px solid var(--color-accent)' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
        <AlertCircle size={20} color="var(--color-accent)" />
        <h4 style={{ fontSize: '1.125rem', fontWeight: 700, color: 'var(--color-text)', margin: 0 }}>
          Scope &amp; Scan Limitations
        </h4>
      </div>

      <p style={{ fontSize: '0.875rem', color: 'var(--color-text-secondary)', lineHeight: 1.5, margin: 0 }}>
        VulnScan Lite provides automated passive external security assessments. To ensure responsible and safe analysis, the engine operates within strictly bounded operational parameters:
      </p>

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
          gap: '0.875rem',
          fontSize: '0.8125rem',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.5rem', background: 'var(--color-bg-secondary)', padding: '0.75rem', borderRadius: 'var(--radius-sm)' }}>
          <CheckCircle2 size={15} color="var(--color-primary)" style={{ marginTop: '2px', flexShrink: 0 }} />
          <div>
            <strong style={{ color: 'var(--color-text)' }}>Passive External Analysis Only:</strong> All inspection is non-intrusive. The scanner never sends malicious exploit payloads, SQL injection tests, or fuzzing streams.
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.5rem', background: 'var(--color-bg-secondary)', padding: '0.75rem', borderRadius: 'var(--radius-sm)' }}>
          <CheckCircle2 size={15} color="var(--color-primary)" style={{ marginTop: '2px', flexShrink: 0 }} />
          <div>
            <strong style={{ color: 'var(--color-text)' }}>No Authenticated Testing:</strong> The scan analyzes publicly reachable endpoints and does not authenticate, bypass credentials, or test role-based access control.
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.5rem', background: 'var(--color-bg-secondary)', padding: '0.75rem', borderRadius: 'var(--radius-sm)' }}>
          <CheckCircle2 size={15} color="var(--color-primary)" style={{ marginTop: '2px', flexShrink: 0 }} />
          <div>
            <strong style={{ color: 'var(--color-text)' }}>Business Logic &amp; Zero-Days:</strong> Deep backend logic flaws, multi-step application vulnerabilities, and unadvertised zero-days cannot be detected via passive analysis.
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.5rem', background: 'var(--color-bg-secondary)', padding: '0.75rem', borderRadius: 'var(--radius-sm)' }}>
          <CheckCircle2 size={15} color="var(--color-primary)" style={{ marginTop: '2px', flexShrink: 0 }} />
          <div>
            <strong style={{ color: 'var(--color-text)' }}>No Guarantee of Absolute Security:</strong> A high score indicates strong baseline HTTP and SSL/TLS configuration, but does not prove the total absence of security vulnerabilities.
          </div>
        </div>
      </div>
    </div>
  );
};

export default ScanLimitations;
