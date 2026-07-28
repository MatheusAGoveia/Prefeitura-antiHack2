'use client';

import React, { useState } from 'react';
import { createTenant } from '@/lib/api/tenants';
import { CreateTenantPayload } from '@/types';
import { Input } from '@/components/ui/Input';
import { Button } from '@/components/ui/Button';
import { X, Building2, Plus } from 'lucide-react';

interface TenantFormModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
}

export function TenantFormModal({ isOpen, onClose, onSuccess }: TenantFormModalProps) {
  const [name, setName] = useState('');
  const [slug, setSlug] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);

    if (!name.trim() || !slug.trim()) {
      setErrorMessage('Preencha os campos obrigatórios (Nome e Slug).');
      return;
    }

    setIsSubmitting(true);
    try {
      const payload: CreateTenantPayload = {
        name: name.trim(),
        slug: slug.trim().toLowerCase().replace(/\s+/g, '-'),
      };
      await createTenant(payload);
      setName('');
      setSlug('');
      onSuccess();
      onClose();
    } catch (err: any) {
      const detail = err?.response?.data?.detail || 'Erro ao cadastrar tenant. Verifique sua permissão.';
      setErrorMessage(typeof detail === 'string' ? detail : JSON.stringify(detail));
    } font-mono finally {
      setIsSubmitting(false);
    }
  };

  const handleNameChange = (val: string) => {
    setName(val);
    // Auto generate slug if user hasn't manually edited it much
    const generatedSlug = val.toLowerCase().trim().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
    setSlug(generatedSlug);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
      <div className="bg-[#121824] border border-[#1e293b] rounded-xl w-full max-w-md p-6 shadow-2xl space-y-5 animate-in fade-in zoom-in duration-150">
        <div className="flex items-center justify-between border-b border-[#1e293b] pb-4">
          <div className="flex items-center gap-2 text-slate-100">
            <Building2 className="w-5 h-5 text-cyan-400" />
            <h3 className="font-semibold text-base">Novo Tenant Municipal</h3>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-slate-200">
            <X className="w-5 h-5" />
          </button>
        </div>

        {errorMessage && (
          <div className="p-3 bg-rose-950/60 border border-rose-800/80 rounded-lg text-rose-300 text-xs font-medium">
            {errorMessage}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <Input
            label="Nome da Entidade / Secretaria"
            placeholder="Ex: Prefeitura de Betim — Saúde"
            value={name}
            onChange={(e) => handleNameChange(e.target.value)}
            required
          />

          <Input
            label="Slug Único (Identificador URL)"
            placeholder="betim-saude"
            value={slug}
            onChange={(e) => setSlug(e.target.value)}
            helperText="Será utilizado em rotas e políticas de isolamento de dados (RLS)."
            required
          />

          <div className="flex items-center justify-end gap-3 pt-4 border-t border-[#1e293b]">
            <Button type="button" variant="ghost" onClick={onClose} disabled={isSubmitting}>
              Cancelar
            </Button>
            <Button type="submit" variant="primary" disabled={isSubmitting} className="gap-2">
              <Plus className="w-4 h-4" />
              {isSubmitting ? 'Cadastrando...' : 'Criar Tenant'}
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
}
