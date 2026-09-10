/**
 * src/pages/Login.tsx — Enterprise login page
 */
import React, { useState } from 'react';
import { Navigate } from 'react-router-dom';
import { Shield, Eye, EyeOff, AlertCircle } from 'lucide-react';
import { useAuthStore } from '../stores/authStore';

export function Login() {
  const { isAuthenticated, login, isLoading } = useAuthStore();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');

  if (isAuthenticated) return <Navigate to="/dashboard" replace />;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    try {
      await login(email, password);
    } catch {
      setError('Invalid email or password');
    }
  };

  return (
    <div className="min-h-screen bg-sentinel-bg flex">
      {/* Left — branding */}
      <div className="hidden lg:flex flex-col justify-between w-1/2 bg-sentinel-surface border-r border-sentinel-border p-12">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 bg-sentinel-accent rounded-xl flex items-center justify-center">
            <Shield size={20} className="text-white" />
          </div>
          <span className="text-xl font-bold text-sentinel-text">IDS Sentinel</span>
        </div>

        <div>
          <h1 className="text-4xl font-bold text-sentinel-text leading-tight mb-4">
            AI-Powered<br />
            <span className="text-sentinel-accent">Network Defense</span>
          </h1>
          <p className="text-sentinel-subtle text-lg leading-relaxed mb-12">
            Real-time intrusion detection powered by XGBoost machine learning.
            Monitor your network, detect threats, and respond instantly.
          </p>

          {/* Feature dots */}
          <div className="space-y-4">
            {[
              { color: 'bg-threat-critical', label: 'Real-time threat detection' },
              { color: 'bg-threat-high', label: '15-class attack classification' },
              { color: 'bg-threat-medium', label: 'Automated alert management' },
              { color: 'bg-threat-info', label: 'Live WebSocket event stream' },
            ].map(({ color, label }) => (
              <div key={label} className="flex items-center gap-3 text-sentinel-subtle text-sm">
                <div className={`w-2 h-2 rounded-full ${color}`} />
                {label}
              </div>
            ))}
          </div>
        </div>

        <div className="text-xs text-sentinel-subtle/60">
          Authorized users only — all access is logged and audited.
        </div>
      </div>

      {/* Right — login form */}
      <div className="flex-1 flex items-center justify-center p-8">
        <div className="w-full max-w-md">
          {/* Mobile logo */}
          <div className="flex items-center gap-3 mb-10 lg:hidden">
            <div className="w-9 h-9 bg-sentinel-accent rounded-lg flex items-center justify-center">
              <Shield size={16} className="text-white" />
            </div>
            <span className="text-lg font-bold text-sentinel-text">IDS Sentinel</span>
          </div>

          <h2 className="text-2xl font-bold text-sentinel-text mb-2">Sign in</h2>
          <p className="text-sentinel-subtle text-sm mb-8">
            Access the security monitoring console
          </p>

          {error && (
            <div className="flex items-center gap-2 bg-threat-critical/10 border border-threat-critical/30 text-threat-critical rounded-lg px-4 py-3 text-sm mb-6 animate-slide-in">
              <AlertCircle size={16} className="flex-shrink-0" />
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-5">
            <div>
              <label className="block text-sm font-medium text-sentinel-text mb-1.5" htmlFor="email">
                Email address
              </label>
              <input
                id="email"
                type="email"
                autoComplete="email"
                required
                className="input w-full"
                placeholder="analyst@company.com"
                value={email}
                onChange={e => setEmail(e.target.value)}
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-sentinel-text mb-1.5" htmlFor="password">
                Password
              </label>
              <div className="relative">
                <input
                  id="password"
                  type={showPassword ? 'text' : 'password'}
                  autoComplete="current-password"
                  required
                  className="input w-full pr-10"
                  placeholder="••••••••"
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-sentinel-subtle hover:text-sentinel-text"
                >
                  {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </div>

            <button
              type="submit"
              id="login-submit"
              disabled={isLoading}
              className="btn-primary w-full flex items-center justify-center gap-2 py-3 disabled:opacity-60"
            >
              {isLoading ? (
                <svg className="animate-spin w-4 h-4" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
              ) : null}
              {isLoading ? 'Signing in…' : 'Sign in'}
            </button>
          </form>

          <p className="mt-8 text-xs text-center text-sentinel-subtle/60">
            All access is logged. Unauthorized access is prohibited.
          </p>
        </div>
      </div>
    </div>
  );
}
