// VulnScan Lite — Scan Progress & Loading State Component

import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { AlertTriangle, Clock, Shield, Server, CheckCircle2, RotateCcw, PlusCircle, Globe, Search, BarChart3, FileCheck, ShieldCheck, Lock } from 'lucide-react';
import type { ScanStatus } from '../types';

interface ScanProgressProps {
  status: ScanStatus;
  stage?: string | null;
  stageMessage?: string | null;
  targetUrl: string;
  scanId: string;
  error?: string | null;
  onRetry?: () => void;
}

const STAGES = [
  { key: 'preparing', label: 'Preparing', icon: Server },
  { key: 'auth_verified', label: 'Authorization verified', icon: ShieldCheck },
  { key: 'validating', label: 'Target validation', icon: Globe },
  { key: 'policy_check', label: 'Security policy validation', icon: Lock },
  { key: 'scanning', label: 'Scanning', icon: Search },
  { key: 'analyzing', label: 'Analysis', icon: BarChart3 },
  { key: 'generating_report', label: 'Report generation', icon: FileCheck },
  { key: 'completed', label: 'Completed', icon: CheckCircle2 },
];

export const ScanProgress: React.FC<ScanProgressProps> = ({
  status,
  stage,
  stageMessage,
  targetUrl,
  scanId,
  error,
  onRetry,
}) => {
  const [elapsed, setElapsed] = useState<number>(0);

  useEffect(() => {
    if (status === 'completed' || status === 'failed') return;

    const timer = setInterval(() => {
      setElapsed((prev) => prev + 1);
    }, 1000);

    return () => clearInterval(timer);
  }, [status]);

  if (status === 'failed') {
    const isReachabilityError =
      error?.toLowerCase().includes('could not be reached') ||
      error?.toLowerCase().includes('connectivity') ||
      error?.toLowerCase().includes('dns') ||
      error?.toLowerCase().includes('timed out');

    return (
      <div
        className="card"
        style={{
          maxWidth: '640px',
          margin: '0 auto',
          padding: '3rem 2rem',
          borderColor: 'rgba(239, 68, 68, 0.4)',
          background: 'rgba(239, 68, 68, 0.04)',
          textAlign: 'center',
        }}
      >
        <div
          style={{
            width: '56px',
            height: '56px',
            borderRadius: '50%',
            background: 'rgba(239, 68, 68, 0.15)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            margin: '0 auto 1.25rem',
          }}
        >
          <AlertTriangle size={28} color="var(--color-danger)" />
        </div>

        <h2 style={{ fontSize: '1.5rem', fontWeight: 800, color: 'var(--color-danger)', marginBottom: '0.75rem' }}>
          {isReachabilityError ? 'Target Could Not Be Reached' : 'Security Scan Failed'}
        </h2>

        <div
          style={{
            background: 'var(--color-bg-secondary)',
            border: '1px solid var(--color-border)',
            borderRadius: 'var(--radius-md)',
            padding: '1.25rem',
            textAlign: 'left',
            margin: '1.5rem 0',
            fontSize: '0.875rem',
            color: 'var(--color-text)',
            whiteSpace: 'pre-line',
            lineHeight: 1.6,
          }}
        >
          {error || 'An error occurred during target scan execution.'}
        </div>

        <div style={{ display: 'flex', gap: '1rem', justifyContent: 'center', flexWrap: 'wrap' }}>
          {onRetry && (
            <button type="button" onClick={onRetry} className="btn btn-primary">
              <RotateCcw size={16} /> Retry Scan
            </button>
          )}
          <Link to="/scan" className="btn btn-outline">
            <PlusCircle size={16} /> Start New Scan
          </Link>
        </div>

        <div style={{ marginTop: '2rem', fontSize: '0.75rem', color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>
          Target: {targetUrl} &bull; Scan ID: {scanId}
        </div>
      </div>
    );
  }

  const isQueued = status === 'queued';
  const stageKeyMap: Record<string, string> = {
    queued: 'preparing',
    preparing: 'preparing',
    auth_verified: 'auth_verified',
    validating: 'validating',
    policy_check: 'policy_check',
    connecting: 'policy_check',
    scanning: 'scanning',
    analyzing: 'analyzing',
    generating_report: 'generating_report',
    completed: 'completed',
  };
  const effectiveKey = (stage && stageKeyMap[stage]) || (isQueued ? 'auth_verified' : 'validating');
  const currentStageIndex = STAGES.findIndex((s) => s.key === effectiveKey);

  return (
    <div className="card" style={{ maxWidth: '680px', margin: '0 auto', textAlign: 'center', padding: '3.5rem 2rem' }}>
      <div
        className="spinner"
        style={{
          width: '56px',
          height: '56px',
          margin: '0 auto 1.5rem',
          borderWidth: '3px',
          borderTopColor: isQueued ? 'var(--color-warning)' : 'var(--color-accent)',
        }}
      />

      <h2 style={{ fontSize: '1.625rem', fontWeight: 800, marginBottom: '0.375rem' }}>
        {stageMessage || (isQueued ? 'Scan Queued in Worker Pool' : 'Executing Security Checks')}
      </h2>

      <p style={{ color: 'var(--color-text-secondary)', fontSize: '0.9375rem', margin: '0.25rem auto 1.75rem', lineHeight: 1.5 }}>
        Target: <strong style={{ color: 'var(--color-text)' }}>{targetUrl}</strong>
      </p>

      {/* Real-time Status Chips */}
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap', marginBottom: '2rem' }}>
        <span
          className={`badge ${isQueued ? 'badge-warning' : 'badge-info'}`}
          style={{ padding: '0.4rem 0.9rem', fontSize: '0.8125rem', display: 'inline-flex', alignItems: 'center', gap: '6px' }}
        >
          {isQueued ? <Server size={14} /> : <Shield size={14} />}
          Stage: {(stage || status).toUpperCase().replace('_', ' ')}
        </span>

        <span
          className="badge"
          style={{
            padding: '0.4rem 0.9rem',
            fontSize: '0.8125rem',
            background: 'var(--color-bg-secondary)',
            color: 'var(--color-text-secondary)',
            display: 'inline-flex',
            alignItems: 'center',
            gap: '6px',
          }}
        >
          <Clock size={14} color="var(--color-accent)" /> Elapsed: {elapsed}s
        </span>
      </div>

      {/* Real Backend Stage Progression Steps */}
      <div
        style={{
          display: 'flex',
          flexDirection: 'column',
          gap: '0.75rem',
          textAlign: 'left',
          background: 'var(--color-bg-secondary)',
          border: '1px solid var(--color-border)',
          borderRadius: 'var(--radius-md)',
          padding: '1.25rem 1.5rem',
        }}
      >
        <div style={{ fontSize: '0.8125rem', fontWeight: 700, color: 'var(--color-text-secondary)', textTransform: 'uppercase', marginBottom: '0.25rem' }}>
          Live Pipeline Execution
        </div>

        {STAGES.map((s, idx) => {
          const isPassed = currentStageIndex > idx || status === 'completed';
          const isCurrent = currentStageIndex === idx || (idx === 0 && isQueued);
          const Icon = s.icon;

          return (
            <div
              key={s.key}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.75rem',
                fontSize: '0.875rem',
                color: isPassed ? 'var(--color-success)' : isCurrent ? 'var(--color-accent)' : 'var(--color-text-muted)',
                fontWeight: isCurrent ? 700 : 500,
              }}
            >
              {isPassed ? (
                <CheckCircle2 size={18} color="var(--color-success)" style={{ flexShrink: 0 }} />
              ) : isCurrent ? (
                <div
                  className="spinner"
                  style={{ width: '16px', height: '16px', borderWidth: '2px', flexShrink: 0 }}
                />
              ) : (
                <Icon size={16} style={{ flexShrink: 0, opacity: 0.4 }} />
              )}
              <span>{s.label}</span>
              {isCurrent && (
                <span style={{ fontSize: '0.75rem', color: 'var(--color-accent)', marginLeft: 'auto' }}>
                  In Progress...
                </span>
              )}
            </div>
          );
        })}
      </div>

      <div style={{ marginTop: '2rem', fontSize: '0.75rem', color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>
        Scan Reference ID: {scanId}
      </div>
    </div>
  );
};

export default ScanProgress;

