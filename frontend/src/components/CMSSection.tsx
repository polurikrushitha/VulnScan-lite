// VulnScan Lite — CMS Fingerprinting Section

import React from 'react';
import { Layers, AlertCircle } from 'lucide-react';
import type { CMSData } from '../types';

interface CMSSectionProps {
  cms?: CMSData;
}

export const CMSSection: React.FC<CMSSectionProps> = ({ cms }) => {
  if (!cms || !cms.detected) {
    return (
      <div className="card" style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
        <Layers size={24} color="var(--color-text-muted)" />
        <div>
          <h4 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--color-text)' }}>
            Content Management System (CMS)
          </h4>
          <p style={{ fontSize: '0.875rem', color: 'var(--color-text-muted)', marginTop: '2px' }}>
            No known CMS fingerprint (WordPress, Drupal, Joomla, Shopify, Wix, etc.) detected from public assets or headers.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Layers size={20} color="var(--color-accent)" />
          <h4 style={{ fontSize: '1.125rem', fontWeight: 700, color: 'var(--color-text)' }}>
            CMS Fingerprint: {cms.cms_name || 'Detected'}
          </h4>
        </div>
        <span className="badge badge-info">
          Confidence: {cms.confidence || 'Medium'}
        </span>
      </div>

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
          gap: '1rem',
          padding: '1rem',
          background: 'var(--color-bg-secondary)',
          borderRadius: 'var(--radius-md)',
          fontSize: '0.875rem',
        }}
      >
        <div>
          <div style={{ color: 'var(--color-text-muted)', fontSize: '0.8125rem', marginBottom: '0.25rem' }}>CMS Software</div>
          <strong style={{ color: 'var(--color-text)' }}>{cms.cms_name}</strong>
        </div>

        <div>
          <div style={{ color: 'var(--color-text-muted)', fontSize: '0.8125rem', marginBottom: '0.25rem' }}>Exposed Version</div>
          <strong style={{ color: cms.version ? 'var(--color-warning)' : 'var(--color-text)' }}>
            {cms.version || 'Version unavailable'}
          </strong>
        </div>

        <div>
          <div style={{ color: 'var(--color-text-muted)', fontSize: '0.8125rem', marginBottom: '0.25rem' }}>Detection Source</div>
          <strong style={{ color: 'var(--color-text)', fontFamily: 'var(--font-mono)', fontSize: '0.8125rem' }}>
            {cms.detection_source || 'Public asset indicators'}
          </strong>
        </div>

        <div>
          <div style={{ color: 'var(--color-text-muted)', fontSize: '0.8125rem', marginBottom: '0.25rem' }}>Outdated Status</div>
          <strong style={{ color: 'var(--color-text-secondary)' }}>
            {cms.outdated_status || 'Outdated status not determined'}
          </strong>
        </div>
      </div>

      {cms.version_exposed && (
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.5rem', fontSize: '0.8125rem', color: 'var(--color-warning)' }}>
          <AlertCircle size={16} style={{ marginTop: '2px', flexShrink: 0 }} />
          <span>
            Exposing exact CMS version numbers allows malicious actors to cross-reference known CVE vulnerability databases. Consider suppressing public generator meta tags.
          </span>
        </div>
      )}
    </div>
  );
};

export default CMSSection;
