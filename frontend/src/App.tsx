// VulnScan Lite — Main Application & Routing

import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { Layout } from './components/Layout';
import { ProtectedRoute } from './components/ProtectedRoute';
import { ErrorBoundary } from './components/ErrorBoundary';
import { Home } from './pages/Home';
import { Login } from './pages/Login';
import { Register } from './pages/Register';
import { Dashboard } from './pages/Dashboard';
import { Scan } from './pages/Scan';
import { ScanResult } from './pages/ScanResult';
import { History } from './pages/History';

function App() {
  return (
    <ErrorBoundary>
      <Router>
        <Routes>
          {/* Public Landing & Authentication */}
          <Route path="/" element={<Layout />}>
            <Route index element={<Home />} />
          </Route>
          
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />

          {/* Protected Dashboard, Scans, and History */}
          <Route element={<ProtectedRoute><Layout /></ProtectedRoute>}>
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/scan" element={<Scan />} />
            <Route path="/scan/:scanId" element={<ScanResult />} />
            <Route path="/scan/:id" element={<ScanResult />} />
            <Route path="/history" element={<History />} />
          </Route>

          {/* Fallback */}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Router>
    </ErrorBoundary>
  );
}

export default App;
