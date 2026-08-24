// VulnScan Lite — Application Error Boundary

import { Component, type ErrorInfo, type ReactNode } from 'react';
import { AlertTriangle, RefreshCw, Home } from 'lucide-react';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public override state: State = {
    hasError: false,
    error: null,
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  public override componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('Uncaught React Error in VulnScan UI:', error, errorInfo);
  }

  public override render() {
    if (this.state.hasError) {
      return (
        <div
          style={{
            minHeight: '100vh',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '2rem',
            background: 'var(--color-bg)',
            color: 'var(--color-text)',
          }}
        >
          <div
            className="card"
            style={{
              maxWidth: '540px',
              width: '100%',
              textAlign: 'center',
              padding: '3rem 2rem',
              borderColor: 'var(--color-danger)',
              boxShadow: '0 8px 32px rgba(239, 68, 68, 0.15)',
            }}
          >
            <AlertTriangle
              size={52}
              color="var(--color-danger)"
              style={{ margin: '0 auto 1.25rem' }}
            />
            <h2 style={{ fontSize: '1.5rem', fontWeight: 800, marginBottom: '0.75rem' }}>
              Something went wrong
            </h2>
            <p
              style={{
                color: 'var(--color-text-secondary)',
                fontSize: '0.9375rem',
                marginBottom: '1.75rem',
                lineHeight: 1.6,
              }}
            >
              The interface encountered an unexpected rendering error. You can refresh the view or navigate back to the home page.
            </p>

            <div style={{ display: 'flex', justifyContent: 'center', gap: '1rem', flexWrap: 'wrap' }}>
              <button
                type="button"
                className="btn btn-primary"
                onClick={() => window.location.reload()}
              >
                <RefreshCw size={16} /> Reload Page
              </button>
              <a href="/" className="btn btn-outline">
                <Home size={16} /> Return to Home
              </a>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;
