// VulnScan Lite — Scan & History Service

import api from './api';
import type {
  ScanCreatePayload,
  ScanCreateResponse,
  ScanStatusResponse,
  ScanResult,
  ScanHistoryItem,
} from '../types';

export const createScan = async (payload: ScanCreatePayload): Promise<ScanCreateResponse> => {
  const { data } = await api.post<ScanCreateResponse>('/api/scan', {
    ...payload,
    consent_version: payload.consent_version || 'Authorized Scanning Policy v1.0',
  });
  return data;
};

export const getScanStatus = async (scanId: string): Promise<ScanStatusResponse> => {
  const { data } = await api.get<ScanStatusResponse>(`/api/scan/${scanId}/status`);
  return data;
};

export const getScanResult = async (scanId: string): Promise<ScanResult> => {
  const { data } = await api.get<ScanResult>(`/api/scan/${scanId}/result`);
  return data;
};

export const getScanHistory = async (): Promise<ScanHistoryItem[]> => {
  const { data } = await api.get<ScanHistoryItem[]>('/api/scan');
  return data;
};
