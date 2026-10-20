/**
 * src/components/layout/Layout.tsx — App shell layout
 */
import React from 'react';
import { Outlet } from 'react-router-dom';
import { Sidebar } from './Sidebar';
import { useRealtimeEvents } from '../../hooks/useRealtimeEvents';
import { useAuthStore } from '../../stores/authStore';
import { Toaster } from 'react-hot-toast';

export function Layout() {
  const { isAuthenticated } = useAuthStore();
  const realtime = useRealtimeEvents(isAuthenticated);

  return (
    <div className="flex h-screen bg-sentinel-bg overflow-hidden">
      <Sidebar isConnected={realtime.isConnected} />
      <main className="flex-1 overflow-y-auto">
        <Outlet context={realtime} />
      </main>
      <Toaster
        position="top-right"
        toastOptions={{
          style: {
            background: '#0f1629',
            color: '#e2e8f0',
            border: '1px solid #1e2d4a',
          },
        }}
      />
    </div>
  );
}
