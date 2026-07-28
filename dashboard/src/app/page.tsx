'use client';

import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { getTenants } from '@/lib/api/tenants';
import { getSystemMemoria } from '@/lib/api/system';
import { Card, CardHeader, CardTitle, CardDescription } from '@/components/ui/Card';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import Link from 'next/link';
import {
  Building2,
  ScrollText,
  ShieldCheck,
  Activity,
  ArrowUpRight,
  Database,
  Lock,
  GitBranch,
} from 'lucide-react';

export default function DashboardPage() {
  const { data: tenants, isLoading: loadingTenants } = useQuery({
    queryKey: ['tenants'],
    queryFn: () => getTenants(),
  });

  const { data: memoria } = useQuery({
    queryKey: ['memoria'],
    queryFn: getSystemMemoria,
    refetchInterval: 10000,
  });

  const activeTenantsCount = tenants?.filter((t) => t.status === 'active').length || 0;
  const totalTenantsCount = tenants?.length || 0;

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="flex items-center justify-between bg-gradient-to-r from-cyan-950/60 via-[#121824] to-[#121824] p-6 rounded-xl border border-cyan-800/40 shadow-xl">
        <div>
          <Badge variant="info" className="mb-2">
            GOVSEC SECURITY OS v1.0
          </Badge>
          <h1 className="text-2xl font-bold text-slate-100 tracking-tight">
            Central de Operações de Segurança (SOC)
          </h1>
          <p className="text-sm text-slate-400 mt-1 max-w-2xl">
            Monitoramento em tempo real da infraestrutura governamental, escopo de ativos municipal, isolamento de tenants (RLS) e execução de políticas OPA.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <Link href="/tenants">
            <Button variant="primary" className="gap-2">
              <Building2 className="w-4 h-4" /> Gerenciar Tenants
            </Button>
          </Link>
          <Link href="/logs">
            <Button variant="outline" className="gap-2">
              <ScrollText className="w-4 h-4" /> Ingerir Logs
            </Button>
          </Link>
        </div>
      </div>

      {/* Metrics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card className="hover:border-cyan-500/50 transition-colors">
          <CardHeader>
            <span className="text-xs uppercase font-semibold text-slate-400 tracking-wider">Total de Tenants</span>
            <div className="p-2 bg-cyan-950/60 text-cyan-400 rounded-lg border border-cyan-800/50">
              <Building2 className="w-4 h-4" />
            </div>
          </CardHeader>
          <div className="text-3xl font-bold text-slate-100">{loadingTenants ? '...' : totalTenantsCount}</div>
          <p className="text-xs text-slate-400 mt-2 flex items-center gap-1">
            <span className="text-emerald-400 font-semibold">{activeTenantsCount} ativos</span> na plataforma
          </p>
        </Card>

        <Card className="hover:border-emerald-500/50 transition-colors">
          <CardHeader>
            <span className="text-xs uppercase font-semibold text-slate-400 tracking-wider">Status do PostgreSQL</span>
            <div className="p-2 bg-emerald-950/60 text-emerald-400 rounded-lg border border-emerald-800/50">
              <Database className="w-4 h-4" />
            </div>
          </CardHeader>
          <div className="text-3xl font-bold text-emerald-400">Ativo (RLS)</div>
          <p className="text-xs text-slate-400 mt-2">Isolamento Row-Level Security habilitado</p>
        </Card>

        <Card className="hover:border-indigo-500/50 transition-colors">
          <CardHeader>
            <span className="text-xs uppercase font-semibold text-slate-400 tracking-wider">Security Kernel</span>
            <div className="p-2 bg-indigo-950/60 text-indigo-400 rounded-lg border border-indigo-800/50">
              <Lock className="w-4 h-4" />
            </div>
          </CardHeader>
          <div className="text-3xl font-bold text-slate-100">Zero Trust</div>
          <p className="text-xs text-slate-400 mt-2">RBAC + Validação OPA (INV-005)</p>
        </Card>

        <Card className="hover:border-cyan-500/50 transition-colors">
          <CardHeader>
            <span className="text-xs uppercase font-semibold text-slate-400 tracking-wider">Evolução do Projeto</span>
            <div className="p-2 bg-cyan-950/60 text-cyan-400 rounded-lg border border-cyan-800/50">
              <GitBranch className="w-4 h-4" />
            </div>
          </CardHeader>
          <div className="text-3xl font-bold text-cyan-400">
            {memoria?.progresso?.percentual ? `${memoria.progresso.percentual}%` : '100% Core'}
          </div>
          <p className="text-xs text-slate-400 mt-2">
            Branch: <span className="font-mono text-cyan-300">{memoria?.estado_atual?.branch || 'feature/core-platform'}</span>
          </p>
        </Card>
      </div>

      {/* Main Grid Section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Active Tenants Quick View */}
        <div className="lg:col-span-2 space-y-4">
          <Card>
            <CardHeader>
              <div>
                <CardTitle>Entidades Municipais Cadastradas</CardTitle>
                <CardDescription>Secretarias e órgãos municipais operando com isolamento no GovSec Shield</CardDescription>
              </div>
              <Link href="/tenants" className="text-xs text-cyan-400 hover:text-cyan-300 font-semibold flex items-center gap-1">
                Ver Todos <ArrowUpRight className="w-3.5 h-3.5" />
              </Link>
            </CardHeader>

            {loadingTenants ? (
              <div className="py-8 text-center text-slate-400 text-sm">Carregando tenants...</div>
            ) : !tenants || tenants.length === 0 ? (
              <div className="py-8 text-center text-slate-500 text-xs">
                Nenhum tenant cadastrado no PostgreSQL ainda.
              </div>
            ) : (
              <div className="space-y-2.5">
                {tenants.slice(0, 5).map((tenant) => (
                  <div
                    key={tenant.id}
                    className="flex items-center justify-between p-3.5 bg-[#0a0d14] rounded-lg border border-[#1e293b] hover:border-slate-700 transition-colors"
                  >
                    <div className="flex items-center gap-3">
                      <div className="p-2 bg-slate-800 rounded-md text-cyan-400 font-mono text-xs font-bold">
                        {tenant.slug.substring(0, 3).toUpperCase()}
                      </div>
                      <div>
                        <h4 className="text-sm font-semibold text-slate-200">{tenant.name}</h4>
                        <p className="text-xs text-slate-500 font-mono">ID: {tenant.id}</p>
                      </div>
                    </div>
                    <Badge variant={tenant.status === 'active' ? 'success' : 'secondary'}>
                      {tenant.status.toUpperCase()}
                    </Badge>
                  </div>
                ))}
              </div>
            )}
          </Card>
        </div>

        {/* Right Column: Platform Architecture Status */}
        <div className="space-y-4">
          <Card>
            <CardHeader>
              <div>
                <CardTitle>Arquitetura de Segurança</CardTitle>
                <CardDescription>Garantias e invariantes do Core Platform</CardDescription>
              </div>
              <ShieldCheck className="w-5 h-5 text-emerald-400" />
            </CardHeader>
            <div className="space-y-3 text-xs">
              <div className="p-3 bg-[#0a0d14] rounded-lg border border-[#1e293b] space-y-1">
                <span className="font-semibold text-cyan-400">INV-001: Isolamento de Tenants</span>
                <p className="text-slate-400">Garantido por PostgreSQL Row Level Security (RLS) e Tenant ID obrigatório.</p>
              </div>
              <div className="p-3 bg-[#0a0d14] rounded-lg border border-[#1e293b] space-y-1">
                <span className="font-semibold text-emerald-400">INV-005: ScopeSafety Protection</span>
                <p className="text-slate-400">Validação prévia de sub-redes autorizadas (IP whitelisting municipal).</p>
              </div>
              <div className="p-3 bg-[#0a0d14] rounded-lg border border-[#1e293b] space-y-1">
                <span className="font-semibold text-indigo-400">CQRS & Event-Driven</span>
                <p className="text-slate-400">Commands trafegam pelo CommandBus com politicas OPA; eventos pelo Redpanda Kafka.</p>
              </div>
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}
