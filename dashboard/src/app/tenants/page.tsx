'use client';

import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { getTenants } from '@/lib/api/tenants';
import { TenantList } from '@/components/tenants/TenantList';
import { TenantFormModal } from '@/components/tenants/TenantFormModal';
import { Card, CardHeader, CardTitle, CardDescription } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { Building2, Plus, Search, RefreshCw } from 'lucide-react';

export default function TenantsPage() {
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');

  const { data: tenants, isLoading, refetch, isRefetching } = useQuery({
    queryKey: ['tenants'],
    queryFn: () => getTenants(),
  });

  const filteredTenants = tenants?.filter(
    (t) =>
      t.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      t.slug.toLowerCase().includes(searchTerm.toLowerCase()) ||
      t.id.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-[#121824] p-6 rounded-xl border border-[#1e293b]">
        <div>
          <div className="flex items-center gap-2 text-cyan-400 font-semibold text-xs uppercase tracking-wider mb-1">
            <Building2 className="w-4 h-4" /> Gestão de Entidades
          </div>
          <h1 className="text-xl font-bold text-slate-100">Tenants Municipais</h1>
          <p className="text-xs text-slate-400 mt-1">
            Cadastre e acompanhe as secretarias e autarquias municipais configuradas na plataforma GovSec Shield.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <Button variant="ghost" size="sm" onClick={() => refetch()} disabled={isRefetching}>
            <RefreshCw className={`w-4 h-4 ${isRefetching ? 'animate-spin' : ''}`} />
          </Button>
          <Button variant="primary" onClick={() => setIsModalOpen(true)} className="gap-2">
            <Plus className="w-4 h-4" /> Novo Tenant
          </Button>
        </div>
      </div>

      {/* Main Content Card */}
      <Card>
        <CardHeader>
          <div>
            <CardTitle>Listagem de Tenants</CardTitle>
            <CardDescription>Visualização em tempo real dos registros no PostgreSQL</CardDescription>
          </div>

          <div className="w-72">
            <Input
              placeholder="Buscar por nome, slug ou UUID..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="text-xs"
            />
          </div>
        </CardHeader>

        <TenantList tenants={filteredTenants || []} isLoading={isLoading} />
      </Card>

      {/* Create Modal */}
      <TenantFormModal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        onSuccess={() => refetch()}
      />
    </div>
  );
}
