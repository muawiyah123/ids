/**
 * src/App.tsx — Root application component
 *
 * Wires up:
 *  - React Router v7 with all page routes
 *  - TanStack Query client
 *  - Auth store initialization (token → /auth/me on cold load)
 *  - Axios 401 handler (clears auth and redirects to login)
 *  - Protected route guard
 */
import React, { useEffect } from 'react';
import {
  BrowserRouter,
  Routes,
  Route,
  Navigate,
} from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Layout } from './components/layout/Layout';
import { useAuthStore } from './stores/authStore';
import { setUnauthorizedHandler } from './services/api';

// Pages
import { Login } from './pages/Login';
import { Dashboard }  from './pages/Dashboard';
import { Monitor }    from './pages/Monitor';
import { Alerts }     from './pages/Alerts';
import { Detections } from './pages/Detections';
import { Analytics }  from './pages/Analytics';
import { Agents }     from './pages/Agents';
import { Models }     from './pages/Models';
import { Health }     from './pages/Health';
import { Audit }      from './pages/Audit';
import { Settings }   from './pages/Settings';
import { Assistant }  from './pages/Assistant';

// ─── TanStack Query client ────────────────────────────────────────────────────
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      staleTime: 30_000,
      refetchOnWindowFocus: false,
    },
  },
});

// ─── Inner app — has access to router context ─────────────────────────────────
function AppRoutes() {
  const { initialize, isAuthenticated, isInitialized, setInitialized } = useAuthStore();

  useEffect(() => {
    setUnauthorizedHandler(() => useAuthStore.getState().clearSession());
    initialize().finally(setInitialized);
  }, [initialize, setInitialized]);

  if (!isInitialized) {
    return <div className="min-h-screen bg-sentinel-bg" />;
  }

  return (
    <Routes>
      <Route path="/login" element={isAuthenticated ? <Navigate to="/dashboard" replace /> : <Login />} />

      <Route element={isAuthenticated ? <Layout /> : <Navigate to="/login" replace />}>
        <Route index element={<Navigate to="/dashboard" replace />} />
        <Route path="/dashboard"  element={<Dashboard />} />
        <Route path="/monitor"    element={<Monitor />} />
        <Route path="/alerts"     element={<Alerts />} />
        <Route path="/detections" element={<Detections />} />
        <Route path="/analytics"  element={<Analytics />} />
        <Route path="/agents"     element={<Agents />} />
        <Route path="/models"     element={<Models />} />
        <Route path="/health"     element={<Health />} />
        <Route path="/audit"      element={<Audit />} />
        <Route path="/settings"   element={<Settings />} />
        <Route path="/assistant"  element={<Assistant />} />

        {/* Catch-all redirect */}
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Route>
    </Routes>
  );
}

// ─── Root export ──────────────────────────────────────────────────────────────
export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <AppRoutes />
      </BrowserRouter>
    </QueryClientProvider>
  );
}
