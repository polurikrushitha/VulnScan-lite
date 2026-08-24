// VulnScan Lite — Authorized Security Testing Confirmation & Overall Agree/Disagree Workflow

import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Lock,
  Globe,
  UserCheck,
  Building2,
  FileCheck2,
  X,
  ArrowRight,
  ArrowLeft,
  CheckCircle2,
  AlertTriangle,
  Info,
} from 'lucide-react';
import type { AuthorizationType, ScanCreatePayload } from '../types';
import { getMe } from '../services/authService';

interface ConsentModalProps {
  targetUrl: string;
  isOpen: boolean;
  onClose: () => void;
  onConfirm: (payload: ScanCreatePayload) => void;
  loading?: boolean;
}

type OverallAcknowledgment = 'agree' | 'disagree' | null;

interface StatementItem {
  id: number;
  title: string;
  text: string;
}

const STATEMENTS: StatementItem[] = [
  {
    id: 1,
    title: 'OWNERSHIP & EXPLICIT AUTHORIZATION',
    text: 'I own this target or have explicit authorization to test it.',
  },
  {
    id: 2,
    title: 'REQUEST TRANSMISSION ACKNOWLEDGMENT',
    text: 'I understand that VulnScan Lite will send requests to the target.',
  },
  {
    id: 3,
    title: 'AUTHORIZED TESTING PURPOSE',
    text: 'I will use VulnScan Lite only for authorized security testing.',
  },
  {
    id: 4,
    title: 'PASSIVE INSPECTION SCOPE',
    text: 'I understand that the scanner performs passive security analysis.',
  },
  {
    id: 5,
    title: 'LEGAL & OPERATIONAL RESPONSIBILITY',
    text: 'I accept responsibility for ensuring that this scan is authorized.',
  },
];

export const ConsentModal: React.FC<ConsentModalProps> = ({
  targetUrl,
  isOpen,
  onClose,
  onConfirm,
  loading = false,
}) => {
  const [userName, setUserName] = useState<string>('Authenticated User');
  const [userEmail, setUserEmail] = useState<string>('');

  // Step state: 1 = Basis, 2 = Required Acknowledgments (Overall Agree/Disagree), 3 = Target Verification & Summary
  const [currentStep, setCurrentStep] = useState<1 | 2 | 3>(1);

  // Authorization Basis State
  const [authType, setAuthType] = useState<AuthorizationType>('user_owned');

  // Single Overall Acknowledgment State for all 5 statements collectively
  const [acknowledgment, setAcknowledgment] = useState<OverallAcknowledgment>(null);

  // Step 3 Target Verification Checkbox
  const [targetConfirmed, setTargetConfirmed] = useState<boolean>(false);

  // Fetch current user details on modal open
  useEffect(() => {
    if (isOpen) {
      getMe()
        .then((u) => {
          if (u.name) setUserName(u.name);
          if (u.email) setUserEmail(u.email);
        })
        .catch(() => {
          // Keep defaults
        });
    }
  }, [isOpen]);

  // Reset modal state on close or URL change
  useEffect(() => {
    if (!isOpen) {
      setCurrentStep(1);
      setAuthType('user_owned');
      setAcknowledgment(null);
      setTargetConfirmed(false);
    }
  }, [isOpen, targetUrl]);

  if (!isOpen) return null;

  const isAgreed = acknowledgment === 'agree';
  const isDisagreed = acknowledgment === 'disagree';

  const handleFinalSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!isAgreed || !targetConfirmed || loading) return;

    // All 5 conditions are collectively accepted via the single overall Agree selection
    onConfirm({
      url: targetUrl,
      authorization_type: authType,
      target_confirmed: true,
      consent_version: 'Authorized Scanning Policy v1.0',
      confirmed_ownership: true,
      confirmed_requests_acknowledged: true,
      confirmed_authorized_testing_only: true,
      confirmed_passive_analysis_understood: true,
      confirmed_responsibility_accepted: true,
    });
  };

  const getAuthLabel = (type: AuthorizationType) => {
    switch (type) {
      case 'user_owned':
        return 'User-Owned Target';
      case 'organization_approved':
        return 'Organization-Approved Target';
      case 'explicit_permission':
        return 'Explicitly Authorized Target';
      default:
        return 'Confirmed';
    }
  };

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        backgroundColor: 'rgba(5, 8, 22, 0.85)',
        backdropFilter: 'blur(8px)',
        zIndex: 9999,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '1rem',
        overflowY: 'auto',
      }}
      onClick={(e) => {
        if (e.target === e.currentTarget && !loading) onClose();
      }}
    >
      <div
        className="card"
        style={{
          width: '100%',
          maxWidth: '780px',
          maxHeight: '94vh',
          overflowY: 'auto',
          padding: '2rem',
          position: 'relative',
          border: '1px solid rgba(99, 102, 241, 0.35)',
          boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.65), 0 0 35px rgba(99, 102, 241, 0.15)',
        }}
      >
        {/* Close Button */}
        <button
          type="button"
          onClick={onClose}
          disabled={loading}
          style={{
            position: 'absolute',
            top: '1.25rem',
            right: '1.25rem',
            background: 'transparent',
            border: 'none',
            color: 'var(--color-text-muted)',
            cursor: loading ? 'not-allowed' : 'pointer',
            padding: '0.35rem',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            borderRadius: '6px',
          }}
          aria-label="Close"
        >
          <X size={20} />
        </button>

        {/* Modal Header */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.875rem', marginBottom: '1.25rem' }}>
          <div
            style={{
              width: '48px',
              height: '48px',
              borderRadius: '12px',
              background: 'rgba(99, 102, 241, 0.18)',
              border: '1px solid rgba(99, 102, 241, 0.4)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              flexShrink: 0,
            }}
          >
            <ShieldAlert size={28} color="var(--color-accent)" />
          </div>
          <div>
            <h2 style={{ fontSize: '1.45rem', fontWeight: 800, color: 'var(--color-text)', margin: 0 }}>
              Authorized Security Testing Confirmation
            </h2>
            <p style={{ fontSize: '0.875rem', color: 'var(--color-text-secondary)', marginTop: '0.25rem', margin: 0 }}>
              VulnScan Lite requires explicit authorization and consent before dispatching test requests.
            </p>
          </div>
        </div>

        {/* Prominent Affirmation Banner */}
        <div
          style={{
            background: 'linear-gradient(135deg, rgba(99, 102, 241, 0.15), rgba(30, 41, 59, 0.75))',
            border: '1px solid rgba(99, 102, 241, 0.35)',
            borderRadius: 'var(--radius-md)',
            padding: '0.9rem 1.25rem',
            marginBottom: '1.25rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.75rem',
          }}
        >
          <Lock size={18} color="var(--color-accent)" style={{ flexShrink: 0 }} />
          <div style={{ fontSize: '0.9375rem', fontWeight: 600, color: 'var(--color-text)', lineHeight: 1.45 }}>
            &ldquo;I confirm that I own this target or have explicit permission from the owner to perform security testing.&rdquo;
          </div>
        </div>

        {/* Step Indicator Header */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: '0.5rem',
            marginBottom: '1.5rem',
            background: 'var(--color-bg-secondary)',
            padding: '0.5rem 0.75rem',
            borderRadius: 'var(--radius-md)',
            border: '1px solid var(--color-border)',
            flexWrap: 'wrap',
          }}
        >
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              fontSize: '0.8125rem',
              fontWeight: 700,
              color: currentStep === 1 ? 'var(--color-accent)' : 'var(--color-text-secondary)',
            }}
          >
            <span
              style={{
                width: '22px',
                height: '22px',
                borderRadius: '50%',
                background: currentStep === 1 ? 'var(--color-primary)' : 'rgba(255,255,255,0.1)',
                color: '#fff',
                display: 'inline-flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: '0.75rem',
              }}
            >
              1
            </span>
            <span>Authorization Basis</span>
          </div>

          <span style={{ color: 'var(--color-border)' }}>&bull;</span>

          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              fontSize: '0.8125rem',
              fontWeight: 700,
              color: currentStep === 2 ? 'var(--color-accent)' : isAgreed ? 'var(--color-success)' : 'var(--color-text-secondary)',
            }}
          >
            <span
              style={{
                width: '22px',
                height: '22px',
                borderRadius: '50%',
                background: currentStep === 2 ? 'var(--color-primary)' : isAgreed ? 'var(--color-success)' : 'rgba(255,255,255,0.1)',
                color: '#fff',
                display: 'inline-flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: '0.75rem',
              }}
            >
              2
            </span>
            <span>Required Acknowledgments {isAgreed ? '(Agreed ✓)' : ''}</span>
          </div>

          <span style={{ color: 'var(--color-border)' }}>&bull;</span>

          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              fontSize: '0.8125rem',
              fontWeight: 700,
              color: currentStep === 3 ? 'var(--color-accent)' : 'var(--color-text-secondary)',
            }}
          >
            <span
              style={{
                width: '22px',
                height: '22px',
                borderRadius: '50%',
                background: currentStep === 3 ? 'var(--color-primary)' : 'rgba(255,255,255,0.1)',
                color: '#fff',
                display: 'inline-flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: '0.75rem',
              }}
            >
              3
            </span>
            <span>Target Verification</span>
          </div>
        </div>

        {/* ------------------------------------------------------------- */}
        {/* STEP 1: Authorization Basis Selection                          */}
        {/* ------------------------------------------------------------- */}
        {currentStep === 1 && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            <div
              style={{
                background: 'var(--color-bg-secondary)',
                border: '1px solid var(--color-border)',
                borderRadius: 'var(--radius-md)',
                padding: '1.25rem',
                display: 'flex',
                flexDirection: 'column',
                gap: '1rem',
              }}
            >
              <div>
                <div style={{ fontSize: '0.875rem', fontWeight: 800, color: 'var(--color-text)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                  1. Authorization Relationship
                </div>
                <p style={{ fontSize: '0.875rem', color: 'var(--color-text-secondary)', marginTop: '0.25rem' }}>
                  Select the organizational or legal basis under which you are authorized to inspect this endpoint.
                </p>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))', gap: '0.75rem' }}>
                <label
                  style={{
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '0.4rem',
                    padding: '1rem',
                    borderRadius: 'var(--radius-md)',
                    border: `1.5px solid ${authType === 'user_owned' ? 'var(--color-primary)' : 'var(--color-border)'}`,
                    background: authType === 'user_owned' ? 'rgba(99, 102, 241, 0.12)' : 'transparent',
                    cursor: 'pointer',
                    transition: 'all 0.15s ease',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                    <input
                      type="radio"
                      name="authorization_type"
                      value="user_owned"
                      checked={authType === 'user_owned'}
                      onChange={() => setAuthType('user_owned')}
                      disabled={loading}
                    />
                    <UserCheck size={18} color="var(--color-accent)" />
                    <span style={{ fontWeight: 700, fontSize: '0.9rem', color: 'var(--color-text)' }}>
                      User-Owned Target
                    </span>
                  </div>
                  <span style={{ fontSize: '0.8125rem', color: 'var(--color-text-muted)', marginLeft: '1.75rem' }}>
                    You directly own, manage, and operate this host or application.
                  </span>
                </label>

                <label
                  style={{
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '0.4rem',
                    padding: '1rem',
                    borderRadius: 'var(--radius-md)',
                    border: `1.5px solid ${authType === 'organization_approved' ? 'var(--color-primary)' : 'var(--color-border)'}`,
                    background: authType === 'organization_approved' ? 'rgba(99, 102, 241, 0.12)' : 'transparent',
                    cursor: 'pointer',
                    transition: 'all 0.15s ease',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                    <input
                      type="radio"
                      name="authorization_type"
                      value="organization_approved"
                      checked={authType === 'organization_approved'}
                      onChange={() => setAuthType('organization_approved')}
                      disabled={loading}
                    />
                    <Building2 size={18} color="var(--color-accent)" />
                    <span style={{ fontWeight: 700, fontSize: '0.9rem', color: 'var(--color-text)' }}>
                      Organization-Approved
                    </span>
                  </div>
                  <span style={{ fontSize: '0.8125rem', color: 'var(--color-text-muted)', marginLeft: '1.75rem' }}>
                    Your enterprise or team has granted authorized testing authority.
                  </span>
                </label>

                <label
                  style={{
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '0.4rem',
                    padding: '1rem',
                    borderRadius: 'var(--radius-md)',
                    border: `1.5px solid ${authType === 'explicit_permission' ? 'var(--color-primary)' : 'var(--color-border)'}`,
                    background: authType === 'explicit_permission' ? 'rgba(99, 102, 241, 0.12)' : 'transparent',
                    cursor: 'pointer',
                    transition: 'all 0.15s ease',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                    <input
                      type="radio"
                      name="authorization_type"
                      value="explicit_permission"
                      checked={authType === 'explicit_permission'}
                      onChange={() => setAuthType('explicit_permission')}
                      disabled={loading}
                    />
                    <FileCheck2 size={18} color="var(--color-accent)" />
                    <span style={{ fontWeight: 700, fontSize: '0.9rem', color: 'var(--color-text)' }}>
                      Explicitly Authorized
                    </span>
                  </div>
                  <span style={{ fontSize: '0.8125rem', color: 'var(--color-text-muted)', marginLeft: '1.75rem' }}>
                    You hold written permission/contract from the third-party asset owner.
                  </span>
                </label>
              </div>
            </div>

            {/* Step 1 Actions */}
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem', marginTop: '0.5rem' }}>
              <button
                type="button"
                className="btn btn-outline"
                onClick={onClose}
                disabled={loading}
              >
                Cancel
              </button>
              <button
                type="button"
                className="btn btn-primary"
                onClick={() => setCurrentStep(2)}
                disabled={loading}
                style={{ padding: '0.65rem 1.25rem' }}
              >
                Proceed to Acknowledgments <ArrowRight size={16} />
              </button>
            </div>
          </div>
        )}

        {/* ------------------------------------------------------------- */}
        {/* STEP 2: Required Acknowledgments (Single Overall Agree/Disagree) */}
        {/* ------------------------------------------------------------- */}
        {currentStep === 2 && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            <div
              style={{
                background: 'var(--color-bg-secondary)',
                border: '1px solid var(--color-border)',
                borderRadius: 'var(--radius-md)',
                padding: '1.5rem',
                display: 'flex',
                flexDirection: 'column',
                gap: '1.25rem',
              }}
            >
              {/* Section Header */}
              <div>
                <div style={{ fontSize: '1rem', fontWeight: 800, color: 'var(--color-text)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                  3. REQUIRED ACKNOWLEDGMENTS
                </div>
                <p style={{ fontSize: '0.875rem', color: 'var(--color-text-secondary)', marginTop: '0.35rem' }}>
                  Please review all five statements carefully.
                </p>
              </div>

              {/* Numbered Statements List */}
              <div
                style={{
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.875rem',
                  background: 'var(--color-bg-primary)',
                  padding: '1.25rem',
                  borderRadius: 'var(--radius-md)',
                  border: '1px solid var(--color-border)',
                }}
              >
                {STATEMENTS.map((item) => (
                  <div
                    key={item.id}
                    style={{
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '0.2rem',
                      paddingBottom: item.id < 5 ? '0.75rem' : '0',
                      borderBottom: item.id < 5 ? '1px solid rgba(255, 255, 255, 0.06)' : 'none',
                    }}
                  >
                    <div style={{ fontSize: '0.8125rem', fontWeight: 700, color: 'var(--color-accent)' }}>
                      {item.id}. {item.title}
                    </div>
                    <div style={{ fontSize: '0.9375rem', color: 'var(--color-text)', lineHeight: 1.45 }}>
                      &ldquo;{item.text}&rdquo;
                    </div>
                  </div>
                ))}
              </div>

              <hr style={{ border: 'none', borderTop: '1px solid var(--color-border)', margin: '0.25rem 0' }} />

              {/* Single Overall Acknowledgment Radio Group */}
              <div>
                <div style={{ fontSize: '0.875rem', fontWeight: 800, color: 'var(--color-text)', textTransform: 'uppercase', marginBottom: '0.75rem', letterSpacing: '0.04em' }}>
                  OVERALL ACKNOWLEDGMENT
                </div>

                <div
                  role="radiogroup"
                  aria-label="Overall acknowledgment for all five statements"
                  style={{ display: 'flex', alignItems: 'center', gap: '1.25rem', flexWrap: 'wrap' }}
                >
                  {/* Single Agree Radio Button */}
                  <label
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '0.65rem',
                      padding: '0.65rem 1.25rem',
                      borderRadius: 'var(--radius-md)',
                      fontSize: '0.9375rem',
                      fontWeight: isAgreed ? 700 : 500,
                      cursor: 'pointer',
                      border: isAgreed
                        ? '1.5px solid var(--color-success)'
                        : '1px solid var(--color-border)',
                      background: isAgreed
                        ? 'rgba(16, 185, 129, 0.18)'
                        : 'var(--color-bg-secondary)',
                      color: isAgreed ? '#10b981' : 'var(--color-text)',
                      transition: 'all 0.15s ease',
                      userSelect: 'none',
                    }}
                  >
                    <input
                      type="radio"
                      name="overall_acknowledgment"
                      value="agree"
                      checked={isAgreed}
                      onChange={() => setAcknowledgment('agree')}
                      disabled={loading}
                      style={{ cursor: 'pointer', width: '16px', height: '16px' }}
                    />
                    <span>Agree</span>
                  </label>

                  {/* Single Disagree Radio Button */}
                  <label
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '0.65rem',
                      padding: '0.65rem 1.25rem',
                      borderRadius: 'var(--radius-md)',
                      fontSize: '0.9375rem',
                      fontWeight: isDisagreed ? 700 : 500,
                      cursor: 'pointer',
                      border: isDisagreed
                        ? '1.5px solid var(--color-warning)'
                        : '1px solid var(--color-border)',
                      background: isDisagreed
                        ? 'rgba(245, 158, 11, 0.18)'
                        : 'var(--color-bg-secondary)',
                      color: isDisagreed ? 'var(--color-warning)' : 'var(--color-text)',
                      transition: 'all 0.15s ease',
                      userSelect: 'none',
                    }}
                  >
                    <input
                      type="radio"
                      name="overall_acknowledgment"
                      value="disagree"
                      checked={isDisagreed}
                      onChange={() => setAcknowledgment('disagree')}
                      disabled={loading}
                      style={{ cursor: 'pointer', width: '16px', height: '16px' }}
                    />
                    <span>Disagree</span>
                  </label>
                </div>
              </div>

              {/* Feedback Alert: If Agree is selected */}
              {isAgreed && (
                <div
                  style={{
                    background: 'rgba(16, 185, 129, 0.12)',
                    border: '1px solid rgba(16, 185, 129, 0.45)',
                    borderRadius: 'var(--radius-md)',
                    padding: '0.875rem 1rem',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.625rem',
                  }}
                >
                  <CheckCircle2 size={20} color="var(--color-success)" style={{ flexShrink: 0 }} />
                  <div>
                    <div style={{ fontSize: '0.9375rem', fontWeight: 800, color: 'var(--color-success)' }}>
                      ✓ All required acknowledgments accepted
                    </div>
                    <div style={{ fontSize: '0.8125rem', color: 'var(--color-text-secondary)' }}>
                      You have collectively acknowledged all 5 authorization requirements.
                    </div>
                  </div>
                </div>
              )}

              {/* Feedback Alert: If Disagree is selected */}
              {isDisagreed && (
                <div
                  style={{
                    background: 'rgba(245, 158, 11, 0.12)',
                    border: '1px solid rgba(245, 158, 11, 0.4)',
                    borderRadius: 'var(--radius-md)',
                    padding: '0.875rem 1rem',
                    display: 'flex',
                    alignItems: 'flex-start',
                    gap: '0.625rem',
                  }}
                >
                  <AlertTriangle size={18} color="var(--color-warning)" style={{ flexShrink: 0, marginTop: '2px' }} />
                  <div style={{ fontSize: '0.875rem', color: 'var(--color-text)', lineHeight: 1.45 }}>
                    <strong>Scan cannot continue because the required authorization acknowledgment was not accepted.</strong>
                    <div style={{ color: 'var(--color-text-secondary)', marginTop: '0.15rem' }}>
                      Please review the authorization requirements before continuing.
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Step 2 Actions */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '0.75rem', marginTop: '0.5rem' }}>
              <button
                type="button"
                className="btn btn-outline"
                onClick={() => setCurrentStep(1)}
                disabled={loading}
              >
                <ArrowLeft size={16} /> Back to Authorization Basis
              </button>

              <button
                type="button"
                className="btn btn-primary"
                onClick={() => setCurrentStep(3)}
                disabled={!isAgreed || loading}
                style={{ padding: '0.65rem 1.35rem' }}
              >
                Continue to Target Verification <ArrowRight size={16} />
              </button>
            </div>
          </div>
        )}

        {/* ------------------------------------------------------------- */}
        {/* STEP 3: Target Verification & Final Scan Summary               */}
        {/* ------------------------------------------------------------- */}
        {currentStep === 3 && (
          <form onSubmit={handleFinalSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            {/* Target Verification Card */}
            <div
              style={{
                background: 'var(--color-bg-secondary)',
                border: '1px solid var(--color-border)',
                borderRadius: 'var(--radius-md)',
                padding: '1.25rem',
                display: 'flex',
                flexDirection: 'column',
                gap: '0.875rem',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.875rem', fontWeight: 700, color: 'var(--color-text-secondary)', textTransform: 'uppercase' }}>
                <Globe size={16} color="var(--color-accent)" /> Target Verification
              </div>

              <div
                style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: '1rem',
                  fontWeight: 600,
                  color: 'var(--color-primary)',
                  background: 'rgba(99, 102, 241, 0.08)',
                  padding: '0.65rem 0.9rem',
                  borderRadius: '6px',
                  border: '1px solid rgba(99, 102, 241, 0.2)',
                  wordBreak: 'break-all',
                }}
              >
                Target: <span style={{ color: 'var(--color-text)' }}>{targetUrl}</span>
              </div>

              <label
                style={{
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: '0.625rem',
                  fontSize: '0.9rem',
                  cursor: 'pointer',
                  color: targetConfirmed ? 'var(--color-text)' : 'var(--color-text-secondary)',
                  userSelect: 'none',
                }}
              >
                <input
                  type="checkbox"
                  checked={targetConfirmed}
                  onChange={(e) => setTargetConfirmed(e.target.checked)}
                  disabled={loading}
                  style={{ marginTop: '3px' }}
                />
                <span>
                  <strong>Is this the authorized target you intend to scan?</strong> I confirm that this normalized target address accurately reflects the endpoint under test.
                </span>
              </label>
            </div>

            {/* Scan Authorization Summary */}
            <div
              style={{
                background: 'rgba(15, 23, 42, 0.88)',
                border: '1px solid rgba(99, 102, 241, 0.25)',
                borderRadius: 'var(--radius-md)',
                padding: '1.25rem',
                display: 'flex',
                flexDirection: 'column',
                gap: '0.75rem',
              }}
            >
              <div style={{ fontSize: '0.8125rem', fontWeight: 800, color: 'var(--color-accent)', textTransform: 'uppercase', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <Info size={15} /> Scan Authorization Summary
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '170px 1fr', rowGap: '0.45rem', fontSize: '0.875rem' }}>
                <span style={{ color: 'var(--color-text-muted)' }}>User:</span>
                <span style={{ color: 'var(--color-text)', fontWeight: 600 }}>
                  {userName} {userEmail ? `(${userEmail})` : ''}
                </span>

                <span style={{ color: 'var(--color-text-muted)' }}>Target:</span>
                <span style={{ color: 'var(--color-text)', fontFamily: 'var(--font-mono)', fontSize: '0.8125rem', wordBreak: 'break-all' }}>
                  {targetUrl}
                </span>

                <span style={{ color: 'var(--color-text-muted)' }}>Authorization:</span>
                <span style={{ color: 'var(--color-success)', fontWeight: 600 }}>
                  ✓ Confirmed ({getAuthLabel(authType)})
                </span>

                <span style={{ color: 'var(--color-text-muted)' }}>Required Acknowledgments:</span>
                <span style={{ color: 'var(--color-success)', fontWeight: 700 }}>
                  ✓ All 5 Statements Accepted (Overall Consent)
                </span>

                <span style={{ color: 'var(--color-text-muted)' }}>Security Policy:</span>
                <span style={{ color: 'var(--color-accent)', fontWeight: 600 }}>
                  ✓ Active (SSRF, Loopback &amp; Private IP Blocking Enforced)
                </span>

                <span style={{ color: 'var(--color-text-muted)' }}>Scanning Mode:</span>
                <span style={{ color: 'var(--color-text)' }}>Passive Security Analysis (Non-intrusive)</span>
              </div>
            </div>

            {/* Step 3 Actions */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '0.75rem', marginTop: '0.5rem' }}>
              <button
                type="button"
                className="btn btn-outline"
                onClick={() => setCurrentStep(2)}
                disabled={loading}
              >
                <ArrowLeft size={16} /> Back to Statements
              </button>

              <button
                type="submit"
                className="btn btn-primary btn-lg"
                disabled={!targetConfirmed || !isAgreed || loading}
                style={{ minWidth: '220px', justifyContent: 'center' }}
              >
                {loading ? (
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <div className="spinner" style={{ width: '18px', height: '18px', borderWidth: '2px' }} />
                    <span>Verifying &amp; Launching...</span>
                  </div>
                ) : (
                  <>
                    <ShieldCheck size={18} /> Start Authorized Scan <ArrowRight size={16} />
                  </>
                )}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
};

export default ConsentModal;
