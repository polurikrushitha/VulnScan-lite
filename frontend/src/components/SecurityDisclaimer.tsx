// VulnScan Lite — Reusable Security Disclaimer Component

import React from 'react';
import { ShieldAlert } from 'lucide-react';

interface SecurityDisclaimerProps {
  style?: React.CSSProperties;
}

export const SecurityDisclaimer: React.FC<SecurityDisclaimerProps> = ({ style }) => {
  return (
    <aside
      aria-label="Security Scanning Disclaimer"
      className="disclaimer"
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: '0.875rem',
        ...style,
      }}
    >
      <ShieldAlert size={22} style={{ color: 'var(--color-accent)', flexShrink: 0 }} />
      <div>
        <strong>Ethical & Passive Scanning Notice:</strong> Only scan websites you own or have explicit permission to test.
        VulnScan Lite performs passive security analysis only and does not execute active exploits or destructive payloads.
      </div>
    </aside>
  );
};

export default SecurityDisclaimer;
