// VulnScan Lite — Report Download Service

import { getToken } from './authService';

const baseURL =
  import.meta.env.VITE_API_BASE_URL ||
  (import.meta.env.PROD ? 'https://vulnscan-lite-gxs6.onrender.com' : '');

export const downloadPDFReport = async (scanId: string): Promise<void> => {
  const token = getToken();
  const url = `${baseURL}/api/reports/${scanId}/pdf`;

  const response = await fetch(url, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });

  if (!response.ok) {
    if (response.status === 403) {
      throw new Error('You do not have permission to download this report.');
    }
    if (response.status === 400) {
      const data = await response.json().catch(() => ({}));
      throw new Error(data.detail || 'Scan report is not yet complete.');
    }
    if (response.status === 404) {
      throw new Error('Scan report not found.');
    }
    throw new Error('Failed to generate PDF report. Please try again later.');
  }

  const blob = await response.blob();
  const downloadUrl = window.URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = downloadUrl;
  anchor.download = `vulnscan-${scanId.slice(0, 8)}-report.pdf`;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.URL.revokeObjectURL(downloadUrl);
};
