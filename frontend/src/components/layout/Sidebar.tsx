/**
 * src/components/layout/Sidebar.tsx — Enterprise SOC sidebar navigation
 */
import React from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import {
  Shield, LayoutDashboard, Radio, Bell, Search,
  BarChart3, Server, Cpu, ClipboardList, Settings, LogOut, Wifi, WifiOff,
} from 'lucide-react';
import { useAuthStore } from '../../stores/authStore';
import { cn } from '../../lib/utils';

interface NavItem {
  path: string;
  icon: React.ReactNode;
  label: string;
  roles?: string[];
}

const NAV_ITEMS: NavItem[] = [
  { path: '/dashboard', icon: <LayoutDashboard size={18} />, label: 'Dashboard' },
  { path: '/monitor', icon: <Radio size={18} />, label: 'Live Monitor' },
  { path: '/alerts', icon: <Bell size={18} />, label: 'Alerts' },
  { path: '/detections', icon: <Search size={18} />, label: 'Detections' },
  { path: '/analytics', icon: <BarChart3 size={18} />, label: 'Analytics' },
  { path: '/agents', icon: <Server size={18} />, label: 'Agents', roles: ['ADMIN', 'SUPER_ADMIN'] },
  { path: '/models', icon: <Cpu size={18} />, label: 'AI Model' },
  { path: '/audit', icon: <ClipboardList size={18} />, label: 'Audit', roles: ['ADMIN', 'SUPER_ADMIN', 'SOC_ANALYST'] },
  { path: '/health', icon: <BarChart3 size={18} />, label: 'System Health' },
  { path: '/settings', icon: <Settings size={18} />, label: 'Settings' },
];

interface Props {
  isConnected: boolean;
}

export function Sidebar({ isConnected }: Props) {
  const { user, logout } = useAuthStore();

  return (
    <aside className="w-64 bg-sentinel-surface border-r border-sentinel-border flex flex-col h-screen sticky top-0 z-40">
      {/* Logo */}
      <div className="flex items-center gap-3 px-6 py-5 border-b border-sentinel-border">
        <div className="w-8 h-8 bg-sentinel-accent rounded-lg flex items-center justify-center">
          <Shield size={16} className="text-white" />
        </div>
        <div>
          <div className="text-sm font-bold text-sentinel-text leading-none">IDS Sentinel</div>
          <div className="text-xs text-sentinel-subtle mt-0.5">AI Network Defense</div>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 px-3 py-4 space-y-0.5 overflow-y-auto">
        {NAV_ITEMS.map((item) => {
          if (item.roles && user && !item.roles.includes(user.role)) return null;
          return (
            <NavLink
              key={item.path}
              to={item.path}
              className={({ isActive }) =>
                cn(
                  'flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-all',
                  isActive
                    ? 'bg-sentinel-accent/15 text-sentinel-accent font-medium'
                    : 'text-sentinel-subtle hover:bg-sentinel-panel hover:text-sentinel-text'
                )
              }
            >
              {item.icon}
              {item.label}
            </NavLink>
          );
        })}
      </nav>

      {/* Bottom status + user */}
      <div className="px-3 py-4 border-t border-sentinel-border space-y-2">
        {/* WebSocket status */}
        <div className={cn(
          'flex items-center gap-2 px-3 py-2 rounded-lg text-xs',
          isConnected
            ? 'text-threat-info'
            : 'text-sentinel-subtle'
        )}>
          {isConnected
            ? <Wifi size={14} className="flex-shrink-0" />
            : <WifiOff size={14} className="flex-shrink-0" />}
          <span>{isConnected ? 'Live feed connected' : 'Reconnecting…'}</span>
          {isConnected && <span className="ml-auto w-1.5 h-1.5 bg-threat-info rounded-full animate-pulse" />}
        </div>

        {/* User info */}
        <div className="flex items-center gap-3 px-3 py-2">
          <div className="w-7 h-7 bg-sentinel-accent rounded-full flex items-center justify-center text-white text-xs font-bold flex-shrink-0">
            {user?.email?.[0]?.toUpperCase() ?? '?'}
          </div>
          <div className="flex-1 min-w-0">
            <div className="text-xs font-medium text-sentinel-text truncate">{user?.email}</div>
            <div className="text-xs text-sentinel-subtle">{user?.role?.replace('_', ' ')}</div>
          </div>
          <button
            onClick={() => logout()}
            className="text-sentinel-subtle hover:text-threat-critical transition-colors p-1 rounded"
            title="Logout"
          >
            <LogOut size={14} />
          </button>
        </div>
      </div>
    </aside>
  );
}
