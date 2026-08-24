// VulnScan Lite — Dedicated Technology Information Section (Informational)

import React, { useState } from 'react';
import { Cpu, Server, Layers, FileCode, ChevronDown, ChevronRight, Info, Terminal } from 'lucide-react';
import type { HeaderData, CMSData, HTMLData } from '../types';

interface TechnologySectionProps {
  headerData?: HeaderData;
  cms?: CMSData;
  htmlData?: HTMLData;
}

export const TechnologySection: React.FC<TechnologySectionProps> = ({
  headerData,
  cms,
  htmlData,
}) => {
  const [showTechnicalDetails, setShowTechnicalDetails] = useState<boolean>(false);

  const serverHeader = headerData?.server;
  const xPoweredBy = headerData?.x_powered_by;
  const cmsDetected = cms?.detected;
  const clientLibs = htmlData?.technology_indicators || [];
  const generatorTag = htmlData?.generator;

  const hasAnyTech = serverHeader || xPoweredBy || cmsDetected || clientLibs.length > 0 || generatorTag;

  return (
    <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* Title & Info Banner */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '0.75rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Cpu size={20} color="var(--color-primary)" />
          <h4 style={{ fontSize: '1.125rem', fontWeight: 700, color: 'var(--color-text)', margin: 0 }}>
            Technology Information
          </h4>
        </div>
        <span className="badge badge-info" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
          <Info size={12} /> Informational
        </span>
      </div>

      <div
        style={{
          fontSize: '0.8125rem',
          color: 'var(--color-text-secondary)',
          background: 'rgba(99, 102, 241, 0.05)',
          border: '1px solid rgba(99, 102, 241, 0.15)',
          borderRadius: 'var(--radius-sm)',
          padding: '0.625rem 0.875rem',
        }}
      >
        Technology fingerprinting is informational and does not by itself indicate a vulnerability.
      </div>

      {!hasAnyTech ? (
        <div style={{ color: 'var(--color-text-muted)', fontSize: '0.875rem', fontStyle: 'italic', padding: '1rem 0' }}>
          No server banners, CMS platforms, or framework signatures were publicly disclosed by the target.
        </div>
      ) : (
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
          {/* Web Server */}
          {serverHeader && (
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem', color: 'var(--color-text-muted)', fontSize: '0.8125rem', marginBottom: '0.25rem' }}>
                <Server size={14} /> Web Server
              </div>
              <strong style={{ color: 'var(--color-text)', fontFamily: 'var(--font-mono)' }}>{serverHeader}</strong>
            </div>
          )}

          {/* X-Powered-By */}
          {xPoweredBy && (
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem', color: 'var(--color-text-muted)', fontSize: '0.8125rem', marginBottom: '0.25rem' }}>
                <Terminal size={14} /> Runtime Framework
              </div>
              <strong style={{ color: 'var(--color-text)', fontFamily: 'var(--font-mono)' }}>{xPoweredBy}</strong>
            </div>
          )}

          {/* CMS Platform */}
          {cmsDetected && (
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem', color: 'var(--color-text-muted)', fontSize: '0.8125rem', marginBottom: '0.25rem' }}>
                <Layers size={14} /> CMS Platform
              </div>
              <strong style={{ color: 'var(--color-text)' }}>
                {cms.cms_name} {cms.version ? `(${cms.version})` : ''}
              </strong>
            </div>
          )}

          {/* HTML Generator */}
          {generatorTag && (
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem', color: 'var(--color-text-muted)', fontSize: '0.8125rem', marginBottom: '0.25rem' }}>
                <FileCode size={14} /> Generator Tag
              </div>
              <strong style={{ color: 'var(--color-text)' }}>{generatorTag}</strong>
            </div>
          )}
        </div>
      )}

      {/* Client Libraries & CDNs */}
      {clientLibs.length > 0 && (
        <div>
          <div style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--color-text-secondary)', marginBottom: '0.5rem' }}>
            Detected Client Libraries &amp; CDNs
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
            {clientLibs.map((tech, idx) => (
              <span
                key={idx}
                style={{
                  fontSize: '0.8125rem',
                  padding: '4px 10px',
                  borderRadius: '6px',
                  background: 'rgba(255, 255, 255, 0.05)',
                  border: '1px solid var(--color-border)',
                  color: 'var(--color-text)',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '6px',
                }}
              >
                <FileCode size={13} color="var(--color-accent)" /> {tech}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Expandable Secondary Technical Diagnostics */}
      <div style={{ borderTop: '1px solid var(--color-border)', paddingTop: '0.75rem' }}>
        <button
          type="button"
          onClick={() => setShowTechnicalDetails(!showTechnicalDetails)}
          style={{
            background: 'none',
            border: 'none',
            color: 'var(--color-text-secondary)',
            fontSize: '0.8125rem',
            fontWeight: 600,
            display: 'inline-flex',
            alignItems: 'center',
            gap: '0.375rem',
            cursor: 'pointer',
            padding: '0.25rem 0',
          }}
        >
          {showTechnicalDetails ? <ChevronDown size={15} /> : <ChevronRight size={15} />}
          <span>{showTechnicalDetails ? 'Hide Technical Details' : 'View Safe Technical Details'}</span>
        </button>

        {showTechnicalDetails && (
          <div
            style={{
              marginTop: '0.75rem',
              padding: '0.875rem',
              background: 'var(--color-bg-secondary)',
              borderRadius: 'var(--radius-sm)',
              fontSize: '0.8125rem',
              display: 'flex',
              flexDirection: 'column',
              gap: '0.5rem',
            }}
          >
            {htmlData?.title && (
              <div>
                <span style={{ color: 'var(--color-text-muted)' }}>Page Title: </span>
                <strong style={{ color: 'var(--color-text)' }}>{htmlData.title}</strong>
              </div>
            )}
            {cms?.detection_source && (
              <div>
                <span style={{ color: 'var(--color-text-muted)' }}>CMS Source: </span>
                <code style={{ color: 'var(--color-accent)', fontFamily: 'var(--font-mono)' }}>{cms.detection_source}</code>
              </div>
            )}
            {headerData?.raw_headers && (
              <div style={{ marginTop: '0.25rem' }}>
                <span style={{ color: 'var(--color-text-muted)', display: 'block', marginBottom: '0.25rem' }}>
                  Observed Response Header Keys ({Object.keys(headerData.raw_headers).length}):
                </span>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.375rem' }}>
                  {Object.keys(headerData.raw_headers).map((h) => (
                    <span
                      key={h}
                      style={{
                        fontFamily: 'var(--font-mono)',
                        fontSize: '0.6875rem',
                        padding: '2px 6px',
                        borderRadius: '3px',
                        background: 'rgba(255, 255, 255, 0.04)',
                        border: '1px solid var(--color-border)',
                        color: 'var(--color-text-secondary)',
                      }}
                    >
                      {h}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default TechnologySection;
