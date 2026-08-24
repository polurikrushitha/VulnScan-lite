// VulnScan Lite — Clean SSL/TLS Cryptographic Inspection Component

import React from 'react';
import { Lock, ShieldAlert, Key, Calendar, FileText, CheckCircle2, XCircle, ShieldCheck } from 'lucide-react';
import type { SSLData } from '../types';

interface SSLSectionProps {
  ssl?: SSLData;
}

export const SSLSection: React.FC<SSLSectionProps> = ({ ssl }) => {
  if (!ssl || ssl.connection_successful === false) {
    return (
      <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Lock size={20} color="var(--color-primary)" />
          <h4 style={{ fontSize: '1.125rem', fontWeight: 700, color: 'var(--color-text)', margin: 0 }}>
            SSL / TLS Cryptographic Inspection
          </h4>
        </div>
        <div style={{ color: 'var(--color-text-muted)', fontSize: '0.875rem', fontStyle: 'italic', padding: '1rem 0' }}>
          TLS information unavailable.
        </div>
      </div>
    );
  }

  const getStatusBadge = () => {
    if (!ssl.is_https) {
      return (
        <span className="badge badge-danger" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
          <XCircle size={12} /> Plaintext HTTP (No TLS)
        </span>
      );
    }
    if (ssl.certificate_expired) {
      return (
        <span className="badge badge-danger" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
          <ShieldAlert size={12} /> Certificate Expired
        </span>
      );
    }
    if (ssl.certificate_valid) {
      return (
        <span className="badge badge-success" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
          <CheckCircle2 size={12} /> Certificate Valid
        </span>
      );
    }
    return (
      <span className="badge badge-warning" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
        <ShieldAlert size={12} /> Verification Failed
      </span>
    );
  };

  return (
    <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* Section Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.75rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Lock size={20} color="var(--color-primary)" />
          <h4 style={{ fontSize: '1.125rem', fontWeight: 700, color: 'var(--color-text)', margin: 0 }}>
            SSL / TLS Cryptographic Inspection
          </h4>
        </div>
        {getStatusBadge()}
      </div>

      {ssl.description && (
        <p style={{ fontSize: '0.875rem', color: 'var(--color-text-secondary)', lineHeight: 1.5, margin: 0 }}>
          {ssl.description}
        </p>
      )}

      {/* Grid of Key TLS Parameters */}
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
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem', color: 'var(--color-text-muted)', fontSize: '0.8125rem', marginBottom: '0.25rem' }}>
            <ShieldCheck size={14} /> HTTPS Status
          </div>
          <strong style={{ color: ssl.is_https ? 'var(--color-success)' : 'var(--color-danger)' }}>
            {ssl.is_https ? 'Enabled (Encrypted Transport)' : 'Disabled (Plaintext Transport)'}
          </strong>
        </div>

        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem', color: 'var(--color-text-muted)', fontSize: '0.8125rem', marginBottom: '0.25rem' }}>
            <CheckCircle2 size={14} /> Certificate Validity
          </div>
          <strong style={{ color: ssl.certificate_valid ? 'var(--color-success)' : 'var(--color-danger)' }}>
            {ssl.certificate_valid ? 'Valid & Trusted' : ssl.certificate_expired ? 'Expired' : 'Verification Failed'}
          </strong>
        </div>

        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem', color: 'var(--color-text-muted)', fontSize: '0.8125rem', marginBottom: '0.25rem' }}>
            <Key size={14} /> TLS Version
          </div>
          <strong style={{ color: 'var(--color-text)' }}>{ssl.tls_version || 'TLS information unavailable.'}</strong>
        </div>

        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem', color: 'var(--color-text-muted)', fontSize: '0.8125rem', marginBottom: '0.25rem' }}>
            <Key size={14} /> Cipher Suite
          </div>
          <strong style={{ color: 'var(--color-text)', wordBreak: 'break-all', fontFamily: 'var(--font-mono)', fontSize: '0.75rem' }}>
            {ssl.cipher || 'TLS information unavailable.'}
          </strong>
        </div>

        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem', color: 'var(--color-text-muted)', fontSize: '0.8125rem', marginBottom: '0.25rem' }}>
            <Calendar size={14} /> Certificate Expiration
          </div>
          <strong style={{ color: 'var(--color-text)' }}>{ssl.not_after || 'N/A'}</strong>
        </div>

        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem', color: 'var(--color-text-muted)', fontSize: '0.8125rem', marginBottom: '0.25rem' }}>
            <Calendar size={14} /> Days Remaining
          </div>
          <strong
            style={{
              color: ssl.days_until_expiry && ssl.days_until_expiry < 30 ? 'var(--color-warning)' : 'var(--color-text)',
            }}
          >
            {ssl.days_until_expiry !== undefined && ssl.days_until_expiry !== null ? `${ssl.days_until_expiry} days` : 'N/A'}
          </strong>
        </div>
      </div>

      {/* Subject & Issuer */}
      {(ssl.subject || ssl.issuer) && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', fontSize: '0.8125rem' }}>
          {ssl.subject && (
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.5rem' }}>
              <FileText size={14} style={{ marginTop: '2px', color: 'var(--color-text-muted)', flexShrink: 0 }} />
              <div>
                <span style={{ color: 'var(--color-text-muted)' }}>Subject: </span>
                <span style={{ color: 'var(--color-text)', fontFamily: 'var(--font-mono)' }}>{ssl.subject}</span>
              </div>
            </div>
          )}
          {ssl.issuer && (
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.5rem' }}>
              <FileText size={14} style={{ marginTop: '2px', color: 'var(--color-text-muted)', flexShrink: 0 }} />
              <div>
                <span style={{ color: 'var(--color-text-muted)' }}>Issuer: </span>
                <span style={{ color: 'var(--color-text)', fontFamily: 'var(--font-mono)' }}>{ssl.issuer}</span>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default SSLSection;
