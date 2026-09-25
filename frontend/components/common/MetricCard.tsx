import React from 'react';
import { cn } from '@/lib/utils';

interface MetricCardProps {
  title: string;
  value: string | number;
  icon: React.ElementType;
  description: string;
  trend?: string;
  severity?: 'low' | 'moderate' | 'high' | 'critical';
}

export const MetricCard = ({ title, value, icon: Icon, description, trend, severity }: MetricCardProps) => {
  const severityColors = {
    low: 'text-emerald-500',
    moderate: 'text-yellow-500',
    high: 'text-amber-500',
    critical: 'text-red-500',
  };

  return (
    <div className="bg-slate-900/50 border border-slate-800 p-4 rounded-lg backdrop-blur-sm hover:border-slate-700 transition-all group">
      <div className="flex items-center justify-between mb-3">
        <div className="p-2 bg-slate-800 rounded-md group-hover:bg-slate-700 transition-colors">
          <Icon className={cn("w-4 h-4", severity ? severityColors[severity] : "text-slate-400")} />
        </div>
        {trend && (
          <span className="text-[10px] font-medium text-emerald-500 bg-emerald-500/10 px-1.5 py-0.5 rounded">
            {trend}
          </span>
        )}
      </div>
      <div>
        <p className="text-slate-500 text-xs font-medium uppercase tracking-wider">{title}</p>
        <h3 className="text-2xl font-bold text-slate-100 mt-1 tabular-nums">{value}</h3>
        <p className="text-slate-600 text-[10px] mt-1">{description}</p>
      </div>
    </div>
  );
};
