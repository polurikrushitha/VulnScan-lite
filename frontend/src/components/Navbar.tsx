// VulnScan Lite — Responsive Navigation Bar

import React, { useState } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { Shield, PlusCircle, History as HistoryIcon, LayoutDashboard, LogOut, LogIn, UserPlus, Menu, X } from 'lucide-react';
import { isAuthenticated, logout } from '../services/authService';

export const Navbar: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const authed = isAuthenticated();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  const isActive = (path: string) => location.pathname === path;

  return (
    <header
      style={{
        background: 'rgba(15, 23, 42, 0.85)',
        backdropFilter: 'blur(12px)',
        borderBottom: '1px solid var(--color-border)',
        position: 'sticky',
        top: 0,
        zIndex: 50,
      }}
    >
      <div className="container" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', height: '4rem' }}>
        {/* Brand */}
        <Link to={authed ? "/dashboard" : "/"} style={{ display: 'flex', alignItems: 'center', gap: '0.625rem', textDecoration: 'none' }}>
          <div
            style={{
              background: 'linear-gradient(135deg, var(--color-primary), var(--color-accent))',
              borderRadius: '8px',
              padding: '6px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <Shield size={20} color="white" />
          </div>
          <span style={{ fontSize: '1.25rem', fontWeight: 800, letterSpacing: '-0.02em', color: 'var(--color-text)' }}>
            VulnScan <span className="gradient-text">Lite</span>
          </span>
        </Link>

        {/* Desktop Navigation */}
        <nav style={{ display: 'none', gap: '1rem', alignItems: 'center' }} className="desktop-nav">
          {authed ? (
            <>
              <Link
                to="/dashboard"
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.375rem',
                  padding: '0.5rem 0.875rem',
                  borderRadius: 'var(--radius-md)',
                  color: isActive('/dashboard') ? 'var(--color-accent)' : 'var(--color-text-secondary)',
                  fontWeight: isActive('/dashboard') ? 600 : 500,
                  fontSize: '0.875rem',
                }}
              >
                <LayoutDashboard size={16} /> Dashboard
              </Link>
              <Link
                to="/scan"
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.375rem',
                  padding: '0.5rem 0.875rem',
                  borderRadius: 'var(--radius-md)',
                  color: isActive('/scan') ? 'var(--color-accent)' : 'var(--color-text-secondary)',
                  fontWeight: isActive('/scan') ? 600 : 500,
                  fontSize: '0.875rem',
                }}
              >
                <PlusCircle size={16} /> New Scan
              </Link>
              <Link
                to="/history"
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.375rem',
                  padding: '0.5rem 0.875rem',
                  borderRadius: 'var(--radius-md)',
                  color: isActive('/history') ? 'var(--color-accent)' : 'var(--color-text-secondary)',
                  fontWeight: isActive('/history') ? 600 : 500,
                  fontSize: '0.875rem',
                }}
              >
                <HistoryIcon size={16} /> History
              </Link>
              <button
                onClick={handleLogout}
                className="btn btn-outline"
                style={{ marginLeft: '0.5rem', padding: '0.4rem 0.875rem', fontSize: '0.8125rem' }}
              >
                <LogOut size={14} /> Logout
              </button>
            </>
          ) : (
            <>
              <Link
                to="/login"
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.375rem',
                  padding: '0.5rem 0.875rem',
                  color: 'var(--color-text-secondary)',
                  fontSize: '0.875rem',
                }}
              >
                <LogIn size={16} /> Login
              </Link>
              <Link to="/register" className="btn btn-primary" style={{ padding: '0.5rem 1rem', fontSize: '0.875rem' }}>
                <UserPlus size={16} /> Register
              </Link>
            </>
          )}
        </nav>

        {/* Mobile menu trigger */}
        <button
          onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
          aria-label={mobileMenuOpen ? 'Close navigation menu' : 'Open navigation menu'}
          style={{
            background: 'transparent',
            border: 'none',
            color: 'var(--color-text)',
            cursor: 'pointer',
            padding: '0.5rem',
            display: 'block',
          }}
          className="mobile-nav-toggle"
        >
          {mobileMenuOpen ? <X size={24} /> : <Menu size={24} />}
        </button>
      </div>

      {/* Mobile menu drawer */}
      {mobileMenuOpen && (
        <div
          style={{
            background: 'var(--color-bg-secondary)',
            borderBottom: '1px solid var(--color-border)',
            padding: '1rem 1.5rem',
            display: 'flex',
            flexDirection: 'column',
            gap: '0.75rem',
          }}
        >
          {authed ? (
            <>
              <Link
                to="/dashboard"
                onClick={() => setMobileMenuOpen(false)}
                style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.5rem 0', color: 'var(--color-text)' }}
              >
                <LayoutDashboard size={18} /> Dashboard
              </Link>
              <Link
                to="/scan"
                onClick={() => setMobileMenuOpen(false)}
                style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.5rem 0', color: 'var(--color-text)' }}
              >
                <PlusCircle size={18} /> New Scan
              </Link>
              <Link
                to="/history"
                onClick={() => setMobileMenuOpen(false)}
                style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.5rem 0', color: 'var(--color-text)' }}
              >
                <HistoryIcon size={18} /> History
              </Link>
              <button
                onClick={() => { setMobileMenuOpen(false); handleLogout(); }}
                className="btn btn-outline"
                style={{ marginTop: '0.5rem', justifyContent: 'center' }}
              >
                <LogOut size={16} /> Logout
              </button>
            </>
          ) : (
            <>
              <Link
                to="/login"
                onClick={() => setMobileMenuOpen(false)}
                style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.5rem 0', color: 'var(--color-text)' }}
              >
                <LogIn size={18} /> Login
              </Link>
              <Link
                to="/register"
                onClick={() => setMobileMenuOpen(false)}
                className="btn btn-primary"
                style={{ justifyContent: 'center' }}
              >
                <UserPlus size={18} /> Register
              </Link>
            </>
          )}
        </div>
      )}
    </header>
  );
};

export default Navbar;
