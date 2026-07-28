'use client';

import React from 'react';
import { Tenant } from '@/types';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/Table';
import { Badge } from '@/components/ui/Badge';
import { Building2, Calendar, Hash, ShieldCheck } from 'lucide-react';

interface TenantListProps {
  tenants: Tenant[];
  isLoading: boolean;
}

export function TenantList({ tenants, isLoading }: TenantListProps) {
  if (isLoading) {
    return (
      <div className="p-8 text-center text-slate-400 bg-[#121824] rounded-xl border border-[#1e293b]">
        <div className="animate-spin inline-block w-6 h-6 border-2 border-cyan-500 border-t-transparent rounded-full mb-2"></div>
        <p className="text-sm">Carregando tenants da prefeitura...</p>
      </div>
    );
  }

  if (!tenants || tenants.length === 0) {
    return (
      <div className="p-12 text-center bg-[#121824] rounded-xl border border-[#1e293b] space-y-3">
        <Building2 className="w-10 h-10 text-slate-600 mx-auto" />
        <h3 className="text-base font-semibold text-slate-300">Nenhum tenant cadastrado</h3>
        <p className="text-xs text-slate-500 max-w-sm mx-auto">
          Utilize o botão "Novo Tenant" acima para cadastrar a primeira secretaria ou entidade municipal.
        </p>
      </div>
    );
  }

  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Identificador (UUID)</TableHead>
          <TableHead>Nome da Entidade</TableHead>
          <TableHead>Slug Identificador</TableHead>
          <TableHead>Status Operacional</TableHead>
          <TableHead>Data de Criação</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {tenants.map((tenant) => (
          <TableRow key={tenant.id}>
            <TableCell className="font-mono text-xs text-cyan-400">
              <div className="flex items-center gap-1.5">
                <Hash className="w-3.5 h-3.5 text-slate-500" />
                <span>{tenant.id}</span>
              </div>
            </TableCell>
            <TableCell className="font-medium text-slate-100">{tenant.name}</TableCell>
            <TableCell>
              <span className="px-2 py-0.5 bg-slate-800 text-slate-300 rounded font-mono text-xs border border-slate-700">
                {tenant.slug}
              </span>
            </TableCell>
            <TableCell>
              <Badge variant={tenant.status === 'active' ? 'success' : 'secondary'}>
                {tenant.status.toUpperCase()}
              </Badge>
            </TableCell>
            <TableCell className="text-xs text-slate-400">
              <div className="flex items-center gap-1.5">
                <Calendar className="w-3.5 h-3.5 text-slate-500" />
                <span>{new Date(tenant.created_at).toLocaleString('pt-BR')}</span>
              </div>
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
