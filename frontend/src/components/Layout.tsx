// VulnScan Lite — Application Layout Component

import React from 'react';
import { Outlet } from 'react-router-dom';
import { Navbar } from './Navbar';
import { SecurityDisclaimer } from './SecurityDisclaimer';

export const Layout: React.FC = () => {
  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      <Navbar />

      <main style={{ flex: 1, padding: '2.5rem 0' }}>
        <div className="container">
          <Outlet />
        </div>
      </main>

      <footer
        style={{
          borderTop: '1px solid var(--color-border)',
          background: 'var(--color-bg-secondary)',
          padding: '2rem 0',
          marginTop: 'auto',
        }}
      >
        <div className="container" style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          <SecurityDisclaimer />
          <div
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              flexWrap: 'wrap',
              gap: '1rem',
              fontSize: '0.8125rem',
              color: 'var(--color-text-muted)',
            }}
          >
            <div>
              &copy; {new Date().getFullYear()} <strong>VulnScan Lite</strong>. All rights reserved.
            </div>
            <div>
              Passive Security Health &amp; Misconfiguration Scanner
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default Layout;
