// VulnScan Lite — Authentication Service

import api from './api';
import type { TokenResponse, User } from '../types';

export const register = async (email: string, password: string, name?: string): Promise<TokenResponse> => {
  const { data } = await api.post<TokenResponse>('/api/auth/register', { email, password, name });
  if (data.access_token) {
    localStorage.setItem('access_token', data.access_token);
  }
  return data;
};

export const login = async (email: string, password: string): Promise<TokenResponse> => {
  const { data } = await api.post<TokenResponse>('/api/auth/login', { email, password });
  if (data.access_token) {
    localStorage.setItem('access_token', data.access_token);
  }
  return data;
};

export const getMe = async (): Promise<User> => {
  const { data } = await api.get<User>('/api/auth/me');
  return data;
};

export const logout = async (): Promise<void> => {
  try {
    await api.post('/api/auth/logout');
  } catch {
    // Ignore error if network fails during logout
  } finally {
    localStorage.removeItem('access_token');
    window.location.href = '/login';
  }
};

export const isAuthenticated = (): boolean => {
  return !!localStorage.getItem('access_token');
};

export const getToken = (): string | null => {
  return localStorage.getItem('access_token');
};

