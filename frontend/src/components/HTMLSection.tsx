// VulnScan Lite — Safe HTML & Metadata Analysis Section

import React from 'react';
import { Code2, FileCode } from 'lucide-react';
import type { HTMLData } from '../types';

interface HTMLSectionProps {
  htmlData?: HTMLData;
}

export const HTMLSection: React.FC<HTMLSectionProps> = ({ htmlData }) => {
  if (!htmlData || htmlData.is_html === false) {
    return (
      <div className="card" style={{ color: 'var(--color-text-muted)', textAlign: 'center', padding: '2rem' }}>
        Target responded with a non-HTML or binary payload; HTML structure analysis was skipped.
      </div>
    );
  }

  return (
    <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
        <Code2 size={20} color="var(--color-primary)" />
        <h4 style={{ fontSize: '1.125rem', fontWeight: 700, color: 'var(--color-text)' }}>
          HTML Metadata &amp; Client Frameworks
        </h4>
      </div>

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
          gap: '1rem',
          padding: '1rem',
          background: 'var(--color-bg-secondary)',
          borderRadius: 'var(--radius-md)',
          fontSize: '0.875rem',
        }}
      >
        <div>
          <div style={{ color: 'var(--color-text-muted)', fontSize: '0.8125rem', marginBottom: '0.25rem' }}>Page Title</div>
          <strong style={{ color: 'var(--color-text)', wordBreak: 'break-word' }}>
            {htmlData.title || 'Untitled Document'}
          </strong>
        </div>

        {htmlData.generator && (
          <div>
            <div style={{ color: 'var(--color-text-muted)', fontSize: '0.8125rem', marginBottom: '0.25rem' }}>Generator Meta</div>
            <strong style={{ color: 'var(--color-text)' }}>{htmlData.generator}</strong>
          </div>
        )}

        {htmlData.form_count !== undefined && (
          <div>
            <div style={{ color: 'var(--color-text-muted)', fontSize: '0.8125rem', marginBottom: '0.25rem' }}>HTML Form Fields</div>
            <strong style={{ color: 'var(--color-text)' }}>{htmlData.form_count} form(s)</strong>
          </div>
        )}

        {htmlData.has_https_links !== undefined && (
          <div>
            <div style={{ color: 'var(--color-text-muted)', fontSize: '0.8125rem', marginBottom: '0.25rem' }}>Internal Links Protocol</div>
            <strong style={{ color: htmlData.has_https_links ? 'var(--color-success)' : 'var(--color-warning)' }}>
              {htmlData.has_https_links ? 'Enforces HTTPS' : 'Contains mixed/HTTP links'}
            </strong>
          </div>
        )}
      </div>

      {htmlData.technology_indicators && htmlData.technology_indicators.length > 0 && (
        <div>
          <div style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--color-text-secondary)', marginBottom: '0.5rem' }}>
            Detected Client Libraries &amp; CDNs
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
            {htmlData.technology_indicators.map((tech, idx) => (
              <span
                key={idx}
                style={{
                  fontSize: '0.8125rem',
                  padding: '4px 10px',
                  borderRadius: '6px',
                  background: 'rgba(99, 102, 241, 0.1)',
                  border: '1px solid rgba(99, 102, 241, 0.25)',
                  color: 'var(--color-text)',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '6px',
                }}
              >
                <FileCode size={14} color="var(--color-accent)" /> {tech}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default HTMLSection;
