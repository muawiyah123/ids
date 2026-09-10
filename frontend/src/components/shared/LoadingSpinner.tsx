/**
 * src/components/shared/LoadingSpinner.tsx
 */
import React from 'react';

interface Props {
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

export function LoadingSpinner({ size = 'md', className = '' }: Props) {
  const sizeClass = { sm: 'w-4 h-4', md: 'w-6 h-6', lg: 'w-10 h-10' }[size];
  return (
    <div className={`${sizeClass} ${className}`}>
      <svg className="animate-spin" fill="none" viewBox="0 0 24 24">
        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
      </svg>
    </div>
  );
}

export function FullPageLoader() {
  return (
    <div className="min-h-screen bg-sentinel-bg flex items-center justify-center">
      <div className="flex flex-col items-center gap-4">
        <LoadingSpinner size="lg" className="text-sentinel-accent" />
        <p className="text-sentinel-subtle text-sm">Loading IDS Sentinel…</p>
      </div>
    </div>
  );
}
