// VulnScan Lite — Insecure HTTP References (Mixed Content) Component

import React, { useState } from 'react';
import { Link2, AlertTriangle, CheckCircle2, ChevronDown, ChevronRight, Globe } from 'lucide-react';

interface InsecureHttpSectionProps {
  insecureHttpLinks?: string[];
  isHttps: boolean;
}

export const InsecureHttpSection: React.FC<InsecureHttpSectionProps> = ({
  insecureHttpLinks = [],
  isHttps,
}) => {
  const [showUrls, setShowUrls] = useState<boolean>(false);
  const detected = isHttps && insecureHttpLinks && insecureHttpLinks.length > 0;
  const count = insecureHttpLinks ? insecureHttpLinks.length : 0;

  return (
    <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.75rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Link2 size={20} color={detected ? 'var(--color-warning)' : 'var(--color-primary)'} />
          <h4 style={{ fontSize: '1.125rem', fontWeight: 700, color: 'var(--color-text)', margin: 0 }}>
            Insecure HTTP References
          </h4>
        </div>

        {detected ? (
          <span
            className="badge badge-warning"
            style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', textTransform: 'uppercase', fontWeight: 700 }}
          >
            <AlertTriangle size={12} /> Detected ({count})
          </span>
        ) : (
          <span
            className="badge badge-success"
            style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', textTransform: 'uppercase', fontWeight: 700 }}
          >
            <CheckCircle2 size={12} /> Not Detected
          </span>
        )}
      </div>

      <p style={{ fontSize: '0.875rem', color: 'var(--color-text-secondary)', lineHeight: 1.5, margin: 0 }}>
        HTTP resources referenced from an HTTPS page may create mixed-content or transport-security concerns depending on how the browser handles the resource.
      </p>

      {detected ? (
        <div
          style={{
            background: 'var(--color-bg-secondary)',
            border: '1px solid var(--color-border)',
            borderRadius: 'var(--radius-md)',
            padding: '1rem',
            display: 'flex',
            flexDirection: 'column',
            gap: '0.75rem',
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '0.8125rem', color: 'var(--color-text)', fontWeight: 600 }}>
              Found {count} resource URL(s) referenced over plaintext HTTP:
            </span>
            <button
              type="button"
              onClick={() => setShowUrls(!showUrls)}
              style={{
                background: 'none',
                border: 'none',
                color: 'var(--color-accent)',
                fontSize: '0.75rem',
                fontWeight: 600,
                cursor: 'pointer',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '2px',
              }}
            >
              {showUrls ? 'Hide URLs' : 'Show Resource URLs'} {showUrls ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
            </button>
          </div>

          {showUrls && (
            <ul style={{ margin: 0, paddingLeft: '1.25rem', display: 'flex', flexDirection: 'column', gap: '0.375rem' }}>
              {insecureHttpLinks.map((url, idx) => (
                <li key={idx} style={{ fontSize: '0.8125rem', color: 'var(--color-text-secondary)' }}>
                  <code style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--color-warning)' }}>
                    {url}
                  </code>
                </li>
              ))}
            </ul>
          )}
        </div>
      ) : (
        <div
          style={{
            padding: '0.75rem 1rem',
            background: 'var(--color-bg-secondary)',
            borderRadius: 'var(--radius-sm)',
            fontSize: '0.8125rem',
            color: 'var(--color-text-muted)',
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
          }}
        >
          <Globe size={14} color="var(--color-success)" />
          No unencrypted HTTP asset references were detected on the target page.
        </div>
      )}
    </div>
  );
};

export default InsecureHttpSection;
