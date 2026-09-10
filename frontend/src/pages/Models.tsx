/**
 * src/pages/Models.tsx — ML Model information page
 */
import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { Cpu, CheckCircle, XCircle, BarChart2 } from 'lucide-react';
import { modelsApi } from '../services/api';
import { LoadingSpinner } from '../components/shared/LoadingSpinner';

export function Models() {
  const { data: model, isLoading } = useQuery({
    queryKey: ['model-current'],
    queryFn: modelsApi.getCurrent,
  });

  const { data: importance } = useQuery({
    queryKey: ['model-importance'],
    queryFn: modelsApi.getImportance,
  });

  if (isLoading) {
    return <div className="flex items-center justify-center h-64"><LoadingSpinner size="lg" className="text-sentinel-accent" /></div>;
  }

  const maxImportance = importance?.features?.[0]?.importance || 1;

  return (
    <div className="p-8 space-y-8">
      <div>
        <h1 className="text-2xl font-bold text-sentinel-text flex items-center gap-3">
          <Cpu size={22} />
          AI Model
        </h1>
        <p className="text-sentinel-subtle text-sm mt-1">XGBoost intrusion detection model</p>
      </div>

      {/* Status + metrics */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        <div className="card p-6">
          <div className="flex items-center gap-3 mb-4">
            {model?.ready
              ? <CheckCircle size={20} className="text-threat-info" />
              : <XCircle size={20} className="text-threat-critical" />}
            <span className="font-semibold text-sentinel-text">
              {model?.ready ? 'Model Ready' : 'Model Unavailable'}
            </span>
          </div>
          <div className="space-y-2 text-sm">
            <div className="flex justify-between"><span className="text-sentinel-subtle">Type</span><span className="font-mono text-xs text-sentinel-text">{model?.model_type || '—'}</span></div>
            <div className="flex justify-between"><span className="text-sentinel-subtle">Version</span><span className="font-mono text-xs text-sentinel-text">{model?.version || '—'}</span></div>
            <div className="flex justify-between"><span className="text-sentinel-subtle">Features</span><span className="font-mono text-xs text-sentinel-text">{model?.feature_count || '—'}</span></div>
            <div className="flex justify-between"><span className="text-sentinel-subtle">Classes</span><span className="font-mono text-xs text-sentinel-text">{model?.class_count || '—'}</span></div>
            {model?.artifact_hash && (
              <div className="pt-2 border-t border-sentinel-border">
                <span className="text-sentinel-subtle text-xs">SHA-256</span>
                <div className="font-mono text-xs text-sentinel-subtle/70 mt-1 break-all">{model.artifact_hash.slice(0, 32)}…</div>
              </div>
            )}
          </div>
        </div>

        <div className="card p-6">
          <h3 className="font-semibold text-sentinel-text mb-4">Test Set Metrics</h3>
          <p className="text-xs text-sentinel-subtle/70 mb-4">Evaluated on CIC-IDS2017 held-out test split. Real-world performance varies.</p>
          <div className="space-y-4">
            {[
              { label: 'Weighted F1', value: model?.metrics?.weighted_f1_test, color: 'bg-threat-info' },
              { label: 'Macro F1', value: model?.metrics?.macro_f1_test, color: 'bg-sentinel-accent' },
              { label: 'Accuracy', value: model?.metrics?.accuracy_test, color: 'bg-threat-medium' },
            ].map(({ label, value, color }) => (
              <div key={label}>
                <div className="flex justify-between text-xs mb-1">
                  <span className="text-sentinel-subtle">{label}</span>
                  <span className="font-mono text-sentinel-text font-medium">{value != null ? (value * 100).toFixed(2) + '%' : '—'}</span>
                </div>
                {value != null && (
                  <div className="bg-sentinel-panel rounded-full h-1.5">
                    <div className={`h-1.5 rounded-full ${color}`} style={{ width: `${value * 100}%` }} />
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>

        <div className="card p-6">
          <h3 className="font-semibold text-sentinel-text mb-4">Supported Classes</h3>
          <div className="space-y-1.5 max-h-64 overflow-y-auto">
            {(model?.classes || []).map((cls: string) => (
              <div key={cls} className="flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-sentinel-accent flex-shrink-0" />
                <span className="text-xs text-sentinel-text">{cls}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Feature importance */}
      {importance?.available && importance.features && (
        <div className="card p-6">
          <div className="flex items-center gap-2 mb-6">
            <BarChart2 size={18} className="text-sentinel-accent" />
            <h3 className="font-semibold text-sentinel-text">Top Feature Importances</h3>
            <span className="text-xs text-sentinel-subtle ml-2">(XGBoost gain — top 20)</span>
          </div>
          <div className="space-y-2.5">
            {importance.features.slice(0, 20).map((f) => (
              <div key={f.feature} className="flex items-center gap-3">
                <span className="text-xs text-sentinel-subtle w-5 text-right">{f.rank}</span>
                <span className="font-mono text-xs text-sentinel-text w-56 truncate">{f.feature}</span>
                <div className="flex-1 bg-sentinel-panel rounded-full h-1.5">
                  <div
                    className="h-1.5 rounded-full bg-sentinel-accent"
                    style={{ width: `${(f.importance / maxImportance) * 100}%` }}
                  />
                </div>
                <span className="font-mono text-xs text-sentinel-subtle w-16 text-right">
                  {(f.importance * 100).toFixed(3)}%
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
