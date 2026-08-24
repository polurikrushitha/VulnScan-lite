// VulnScan Lite — In-Page Report Section Navigation

import React, { useState, useEffect } from 'react';
import { LayoutDashboard, AlertOctagon, ShieldCheck, Lock, Cpu, Link2, AlertCircle } from 'lucide-react';

interface ReportNavProps {
  hasFindings: boolean;
  hasInsecureHttp?: boolean;
}

export const ReportNav: React.FC<ReportNavProps> = ({ hasFindings, hasInsecureHttp }) => {
  const [activeSection, setActiveSection] = useState<string>('executive-summary');

  const navItems = [
    { id: 'executive-summary', label: 'Executive Summary', icon: <LayoutDashboard size={14} /> },
    { id: 'findings', label: `Findings ${hasFindings ? '•' : ''}`, icon: <AlertOctagon size={14} /> },
    { id: 'security-headers', label: 'Security Headers', icon: <ShieldCheck size={14} /> },
    { id: 'tls-https', label: 'TLS / HTTPS', icon: <Lock size={14} /> },
    { id: 'technology-info', label: 'Technology Info', icon: <Cpu size={14} /> },
    ...(hasInsecureHttp ? [{ id: 'insecure-http', label: 'HTTP References', icon: <Link2 size={14} /> }] : []),
    { id: 'limitations', label: 'Limitations', icon: <AlertCircle size={14} /> },
  ];

  useEffect(() => {
    const handleScroll = () => {
      const scrollPos = window.scrollY + 120;
      for (let i = navItems.length - 1; i >= 0; i--) {
        const el = document.getElementById(navItems[i].id);
        if (el && el.offsetTop <= scrollPos) {
          setActiveSection(navItems[i].id);
          break;
        }
      }
    };

    window.addEventListener('scroll', handleScroll, { passive: true });
    return () => window.removeEventListener('scroll', handleScroll);
  }, [navItems]);

  const scrollTo = (id: string) => {
    const el = document.getElementById(id);
    if (el) {
      const yOffset = -80;
      const y = el.getBoundingClientRect().top + window.pageYOffset + yOffset;
      window.scrollTo({ top: y, behavior: 'smooth' });
      setActiveSection(id);
    }
  };

  return (
    <nav
      aria-label="Report section navigation"
      style={{
        position: 'sticky',
        top: '64px',
        zIndex: 20,
        background: 'rgba(15, 23, 42, 0.85)',
        backdropFilter: 'blur(12px)',
        border: '1px solid var(--color-border)',
        borderRadius: 'var(--radius-md)',
        padding: '0.375rem 0.5rem',
        display: 'flex',
        alignItems: 'center',
        gap: '0.375rem',
        overflowX: 'auto',
        marginBottom: '1rem',
      }}
    >
      {navItems.map((item) => {
        const isActive = activeSection === item.id;
        return (
          <button
            key={item.id}
            type="button"
            onClick={() => scrollTo(item.id)}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.375rem',
              padding: '0.4rem 0.75rem',
              borderRadius: 'var(--radius-sm)',
              fontSize: '0.8125rem',
              fontWeight: isActive ? 600 : 500,
              color: isActive ? 'var(--color-primary)' : 'var(--color-text-secondary)',
              background: isActive ? 'rgba(99, 102, 241, 0.15)' : 'transparent',
              border: isActive ? '1px solid rgba(99, 102, 241, 0.3)' : '1px solid transparent',
              cursor: 'pointer',
              whiteSpace: 'nowrap',
              transition: 'all 0.15s ease',
            }}
          >
            {item.icon}
            <span>{item.label}</span>
          </button>
        );
      })}
    </nav>
  );
};

export default ReportNav;
