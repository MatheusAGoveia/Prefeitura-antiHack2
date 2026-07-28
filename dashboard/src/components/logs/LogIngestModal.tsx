'use client';

import React, { useState } from 'react';
import { ingestLog } from '@/lib/api/logs';
import { IngestLogPayload } from '@/types';
import { Input } from '@/components/ui/Input';
import { Button } from '@/components/ui/Button';
import { X, ScrollText, Send } from 'lucide-react';

interface LogIngestModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: (newLog: IngestLogPayload & { id: string; timestamp: string }) => void;
  defaultTenantId?: string;
}

export function LogIngestModal({ isOpen, onClose, onSuccess, defaultTenantId = 'betim' }: LogIngestModalProps) {
  const [source, setSource] = useState('wazuh-agent-01');
  const [tenantId, setTenantId] = useState(defaultTenantId);
  const [jsonString, setJsonString] = useState(
    JSON.stringify({ event: 'AUTHENTICATION_ATTEMPT', ip: '192.168.1.105', status: 'SUCCESS', user: 'admin_betim' }, null, 2)
  );
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);

    let parsedData: Record<string, any>;
    try {
      parsedData = JSON.parse(jsonString);
    } catch {
      setErrorMessage('Payload JSON inválido. Verifique a sintaxe.');
      return;
    }

    setIsSubmitting(true);
    try {
      const payload: IngestLogPayload = {
        source: source.trim(),
        tenant_id: tenantId.trim(),
        raw_data: parsedData,
        timestamp: new Date().toISOString(),
      };
      await ingestLog(payload);
      onSuccess({
        ...payload,
        id: `log-${Date.now().toString(36)}`,
        timestamp: payload.timestamp!,
      });
      onClose();
    } catch (err: any) {
      const detail = err?.response?.data?.detail || 'Erro ao enviar log. Verifique se o papel é ANALYST/SYSTEM_ADMIN.';
      setErrorMessage(typeof detail === 'string' ? detail : JSON.stringify(detail));
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
      <div className="bg-[#121824] border border-[#1e293b] rounded-xl w-full max-w-lg p-6 shadow-2xl space-y-5">
        <div className="flex items-center justify-between border-b border-[#1e293b] pb-4">
          <div className="flex items-center gap-2 text-slate-100">
            <ScrollText className="w-5 h-5 text-cyan-400" />
            <h3 className="font-semibold text-base">Simulador de Ingestão de Log</h3>
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
          <div className="grid grid-cols-2 gap-3">
            <Input
              label="Fonte do Log (Source)"
              placeholder="ex: wazuh-agent, zabbix, firewall-01"
              value={source}
              onChange={(e) => setSource(e.target.value)}
              required
            />
            <Input
              label="Tenant ID / Slug"
              placeholder="betim"
              value={tenantId}
              onChange={(e) => setTenantId(e.target.value)}
              required
            />
          </div>

          <div className="space-y-1.5">
            <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400">
              Raw JSON Data
            </label>
            <textarea
              rows={5}
              className="w-full bg-[#0a0d14] border border-[#1e293b] rounded-lg p-3 text-xs font-mono text-cyan-300 focus:outline-none focus:border-cyan-500"
              value={jsonString}
              onChange={(e) => setJsonString(e.target.value)}
              required
            />
          </div>

          <div className="flex items-center justify-end gap-3 pt-4 border-t border-[#1e293b]">
            <Button type="button" variant="ghost" onClick={onClose} disabled={isSubmitting}>
              Cancelar
            </Button>
            <Button type="submit" variant="primary" disabled={isSubmitting} className="gap-2">
              <Send className="w-4 h-4" />
              {isSubmitting ? 'Enviando...' : 'Enviar para EventBus'}
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
}
