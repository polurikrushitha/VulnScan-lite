// VulnScan Lite — Reusable Scan Status Polling Hook

import { useState, useEffect, useCallback, useRef } from 'react';
import { getScanStatus, getScanResult } from '../services/scanService';
import type { ScanResult, ScanStatus } from '../types';

interface UseScanPollingReturn {
  result: ScanResult | null;
  status: ScanStatus | null;
  stage: string | null;
  stageMessage: string | null;
  loading: boolean;
  error: string | null;
  refetch: () => void;
}

const POLLING_INTERVAL_MS = 1500;
const MAX_POLLING_DURATION_MS = 180000; // 3 minutes client timeout

export const useScanPolling = (scanId: string | undefined): UseScanPollingReturn => {
  const [result, setResult] = useState<ScanResult | null>(null);
  const [status, setStatus] = useState<ScanStatus | null>(null);
  const [stage, setStage] = useState<string | null>(null);
  const [stageMessage, setStageMessage] = useState<string | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const isMountedRef = useRef<boolean>(true);
  const isPollingRef = useRef<boolean>(false);
  const startTimeRef = useRef<number>(Date.now());

  const clearTimer = useCallback(() => {
    if (timerRef.current) {
      clearTimeout(timerRef.current);
      timerRef.current = null;
    }
  }, []);

  const poll = useCallback(async () => {
    if (!scanId || !isMountedRef.current || isPollingRef.current) return;

    // Check timeout
    if (Date.now() - startTimeRef.current > MAX_POLLING_DURATION_MS) {
      if (isMountedRef.current) {
        setError('Scan polling timed out. The background worker may still be processing.');
        setLoading(false);
      }
      return;
    }

    isPollingRef.current = true;

    try {
      // 1. Always poll the STATUS endpoint first
      const statusData = await getScanStatus(scanId);
      if (!isMountedRef.current) return;

      const currentStatus = statusData.status;
      setStatus(currentStatus);
      setStage(statusData.stage || currentStatus);
      setStageMessage(statusData.message || null);

      if (currentStatus === 'completed') {
        // Stop polling and fetch full report once
        clearTimer();
        try {
          const reportData = await getScanResult(scanId);
          if (isMountedRef.current) {
            setResult(reportData);
            setLoading(false);
          }
        } catch (reportErr: any) {
          if (isMountedRef.current) {
            setError(reportErr.response?.data?.detail || 'Failed to retrieve completed scan report.');
            setLoading(false);
          }
        }
      } else if (currentStatus === 'failed') {
        // Stop polling on failure
        clearTimer();
        setError(statusData.error || 'Scan failed to complete.');
        setLoading(false);
      } else {
        // 'queued' or 'running': schedule next status poll in 1.5 seconds
        setLoading(false);
        clearTimer();
        timerRef.current = setTimeout(() => {
          if (isMountedRef.current) {
            poll();
          }
        }, POLLING_INTERVAL_MS);
      }
    } catch (err: any) {
      if (!isMountedRef.current) return;

      const statusCode = err.response?.status;
      const detail = err.response?.data?.detail;

      if (statusCode === 403) {
        setError('You do not have permission to view this scan.');
        setLoading(false);
        clearTimer();
      } else if (statusCode === 404) {
        setError('Scan record not found.');
        setLoading(false);
        clearTimer();
      } else {
        setError(detail || 'Failed to fetch scan status. Please try again.');
        setLoading(false);
        clearTimer();
      }
    } finally {
      isPollingRef.current = false;
    }
  }, [scanId, clearTimer]);

  const refetch = useCallback(() => {
    clearTimer();
    setLoading(true);
    setError(null);
    setResult(null);
    setStage(null);
    setStageMessage(null);
    startTimeRef.current = Date.now();
    poll();
  }, [clearTimer, poll]);

  useEffect(() => {
    isMountedRef.current = true;
    startTimeRef.current = Date.now();
    setLoading(true);
    setError(null);
    setResult(null);
    setStage(null);
    setStageMessage(null);

    if (scanId) {
      poll();
    } else {
      setLoading(false);
    }

    return () => {
      isMountedRef.current = false;
      clearTimer();
    };
  }, [scanId, poll, clearTimer]);

  return { result, status, stage, stageMessage, loading, error, refetch };
};

