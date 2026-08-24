// VulnScan Lite — Central Axios API Client

import axios from 'axios';
import type { AxiosInstance } from 'axios';

// Support configurable backend base URL, defaulting to relative path for Vite proxy
const baseURL = import.meta.env.VITE_API_BASE_URL || '';

export const api: AxiosInstance = axios.create({
  baseURL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Attach JWT access token to every request if present
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('access_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Automatically handle expired tokens or unauthenticated responses
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401 && !window.location.pathname.startsWith('/login') && !window.location.pathname.startsWith('/register')) {
      localStorage.removeItem('access_token');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

/**
 * Extracts a friendly user-facing error message from API errors.
 */
export function formatApiError(error: any): string {
  if (!error) return 'An unexpected error occurred.';
  if (typeof error === 'string') return error;

  if (error.response?.status === 502) {
    return error.response.data?.detail || 'Backend server is unavailable (502 Bad Gateway). Please ensure the FastAPI server is running at http://127.0.0.1:8000.';
  }

  if (error.response?.status === 503) {
    return error.response.data?.detail || 'Backend service is currently unavailable. Please try again in a moment.';
  }

  if (error.response?.status === 504) {
    return 'Gateway timeout. The server took too long to respond.';
  }

  if (error.response?.data?.detail) {
    const detail = error.response.data.detail;
    if (typeof detail === 'string') return detail;
    if (Array.isArray(detail)) {
      return detail.map((d: any) => d.msg || d.message || JSON.stringify(d)).join(', ');
    }
    return JSON.stringify(detail);
  }

  if (error.response?.data?.message) {
    return error.response.data.message;
  }

  if (error.message) {
    if (error.message === 'Network Error' || error.message.includes('ECONNREFUSED')) {
      return 'Unable to connect to the backend server. Please verify the API is running at http://127.0.0.1:8000.';
    }
    return error.message;
  }

  return 'A network or server error occurred. Please try again.';
}


export default api;

