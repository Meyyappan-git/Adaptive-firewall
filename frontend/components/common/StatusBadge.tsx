import React from 'react';
import { cn } from '@/lib/utils';

interface StatusBadgeProps {
  status: string;
  className?: string;
}

export const StatusBadge = ({ status, className }: StatusBadgeProps) => {
  const colors: Record<string, string> = {
    CRITICAL: 'bg-red-500/10 text-red-500 border-red-500/20',
    HIGH: 'bg-amber-500/10 text-amber-500 border-amber-500/20',
    MODERATE: 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20',
    LOW: 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20',
    ACTIVE: 'bg-blue-500/10 text-blue-500 border-blue-500/20',
    EXPIRED: 'bg-slate-500/10 text-slate-500 border-slate-500/20',
    UNACKNOWLEDGED: 'bg-red-500/10 text-red-400 border-red-500/20',
    ACKNOWLEDGED: 'bg-slate-500/10 text-slate-500 border-slate-500/20',
  };

  const style = colors[status.toUpperCase()] || 'bg-slate-500/10 text-slate-400 border-slate-500/20';

  return (
    <span className={cn(
      "px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border",
      style,
      className
    )}>
      {status}
    </span>
  );
};
