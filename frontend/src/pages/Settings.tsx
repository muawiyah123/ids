/**
 * src/pages/Settings.tsx — User settings page
 */
import React, { useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { Settings as SettingsIcon, User, Lock, CheckCircle } from 'lucide-react';
import { authApi } from '../services/api';
import { useAuthStore } from '../stores/authStore';
import toast from 'react-hot-toast';

export function Settings() {
  const { user, login } = useAuthStore();
  const [currentPwd, setCurrentPwd] = useState('');
  const [newPwd, setNewPwd] = useState('');
  const [confirmPwd, setConfirmPwd] = useState('');
  const [pwdError, setPwdError] = useState('');

  const changePwdMutation = useMutation({
    mutationFn: ({ current, next }: { current: string; next: string }) =>
      authApi.changePassword(current, next),
    onSuccess: async (_, variables) => {
      toast.success('Password changed successfully');
      setCurrentPwd('');
      setNewPwd('');
      setConfirmPwd('');
      setPwdError('');
      if (user?.email) {
        try {
          await login(user.email, variables.next);
        } catch {
          // ignore
        }
      }
    },
    onError: (err: any) => {
      const msg = err?.response?.data?.detail || 'Failed to change password — check current password';
      toast.error(msg);
    },
  });

  const handlePasswordChange = (e: React.FormEvent) => {
    e.preventDefault();
    if (newPwd !== confirmPwd) { setPwdError('New passwords do not match'); return; }
    if (newPwd.length < 8) { setPwdError('Password must be at least 8 characters'); return; }
    setPwdError('');
    changePwdMutation.mutate({ current: currentPwd, next: newPwd });
  };

  return (
    <div className="p-8 space-y-8">
      <div>
        <h1 className="text-2xl font-bold text-sentinel-text flex items-center gap-3">
          <SettingsIcon size={22} />
          Settings
        </h1>
        <p className="text-sentinel-subtle text-sm mt-1">Account settings and preferences</p>
      </div>

      {/* Profile */}
      <div className="card p-6">
        <div className="flex items-center gap-3 mb-6">
          <User size={18} className="text-sentinel-accent" />
          <h2 className="font-semibold text-sentinel-text">Profile</h2>
        </div>
        <div className="grid grid-cols-2 gap-6">
          <div>
            <label className="block text-xs font-medium text-sentinel-subtle mb-1">Email</label>
            <div className="input bg-sentinel-bg cursor-not-allowed text-sentinel-subtle">{user?.email}</div>
          </div>
          <div>
            <label className="block text-xs font-medium text-sentinel-subtle mb-1">Full Name</label>
            <div className="input bg-sentinel-bg cursor-not-allowed text-sentinel-subtle">{user?.full_name || '—'}</div>
          </div>
          <div>
            <label className="block text-xs font-medium text-sentinel-subtle mb-1">Role</label>
            <div className="input bg-sentinel-bg cursor-not-allowed text-sentinel-subtle">{user?.role?.replace('_', ' ')}</div>
          </div>
          <div>
            <label className="block text-xs font-medium text-sentinel-subtle mb-1">Account Status</label>
            <div className="flex items-center gap-2 mt-2">
              <CheckCircle size={16} className="text-threat-info" />
              <span className="text-sm text-threat-info">Active</span>
            </div>
          </div>
        </div>
        <p className="text-xs text-sentinel-subtle/60 mt-4">Contact your administrator to update profile information.</p>
      </div>

      {/* Change password */}
      <div className="card p-6">
        <div className="flex items-center gap-3 mb-6">
          <Lock size={18} className="text-sentinel-accent" />
          <h2 className="font-semibold text-sentinel-text">Change Password</h2>
        </div>
        <form onSubmit={handlePasswordChange} className="space-y-4 max-w-md">
          <div>
            <label className="block text-xs font-medium text-sentinel-subtle mb-1">Current Password</label>
            <input type="password" className="input w-full" value={currentPwd} onChange={e => setCurrentPwd(e.target.value)} required />
          </div>
          <div>
            <label className="block text-xs font-medium text-sentinel-subtle mb-1">New Password</label>
            <input type="password" className="input w-full" value={newPwd} onChange={e => setNewPwd(e.target.value)} required minLength={8} />
          </div>
          <div>
            <label className="block text-xs font-medium text-sentinel-subtle mb-1">Confirm New Password</label>
            <input type="password" className="input w-full" value={confirmPwd} onChange={e => setConfirmPwd(e.target.value)} required />
          </div>
          {pwdError && <p className="text-xs text-threat-critical">{pwdError}</p>}
          <button type="submit" disabled={changePwdMutation.isPending} className="btn-primary disabled:opacity-50">
            {changePwdMutation.isPending ? 'Changing…' : 'Change Password'}
          </button>
        </form>
        <p className="text-xs text-sentinel-subtle/60 mt-4">
          Changing your password will revoke all other active sessions.
        </p>
      </div>
    </div>
  );
}
