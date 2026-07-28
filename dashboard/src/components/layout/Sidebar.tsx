'use client';

import React from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { Shield, LayoutDashboard, Building2, ScrollText, ShieldAlert, Cpu } from 'lucide-react';

export function Sidebar() {
  const pathname = usePathname();

  const navItems = [
    { name: 'Visão Geral (SOC)', href: '/', icon: LayoutDashboard },
    { name: 'Tenants', href: '/tenants', icon: Building2 },
    { name: 'Central de Logs', href: '/logs', icon: ScrollText },
    { name: 'ScopeSafety Check', href: '/scope', icon: ShieldAlert },
  ];

  return (
    <aside className="w-64 bg-[#0c1018] border-r border-[#1e293b] min-h-screen flex flex-col justify-between p-4 sticky top-0 h-screen select-none">
      <div>
        {/* Brand Header */}
        <div className="flex items-center gap-3 px-3 py-4 mb-6 border-b border-[#1e293b]/60">
          <div className="p-2 bg-cyan-950/80 text-cyan-400 border border-cyan-800/80 rounded-lg shadow-lg shadow-cyan-950/50">
            <Shield className="w-6 h-6" />
          </div>
          <div>
            <h1 className="font-bold text-slate-100 tracking-wide text-base">GovSec Shield</h1>
            <p className="text-[11px] text-cyan-400 font-mono">Security OS v1.0 MVP</p>
          </div>
        </div>

        {/* Navigation Menu */}
        <nav className="space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = pathname === item.href;
            return (
              <Link
                key={item.href}
                href={item.href}
                className={`flex items-center gap-3 px-3.5 py-2.5 rounded-lg text-sm font-medium transition-all ${
                  isActive
                    ? 'bg-cyan-950/60 text-cyan-300 border border-cyan-800/50 shadow-inner'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-[#131a28]'
                }`}
              >
                <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-500'}`} />
                {item.name}
              </Link>
            );
          })}
        </nav>
      </div>

      {/* Footer Info */}
      <div className="p-3 bg-[#121824] rounded-lg border border-[#1e293b] text-xs text-slate-400 space-y-1.5">
        <div className="flex items-center gap-2 text-emerald-400 font-semibold">
          <Cpu className="w-3.5 h-3.5 animate-pulse" />
          <span>Core Platform Active</span>
        </div>
        <p className="text-[11px] text-slate-500">PostgreSQL + Redpanda Kafka + OPA Policy Engine</p>
      </div>
    </aside>
  );
}
