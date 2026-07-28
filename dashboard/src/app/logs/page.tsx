'use client';

import React, { useState } from 'react';
import { LogList, LogItem } from '@/components/logs/LogList';
import { LogIngestModal } from '@/components/logs/LogIngestModal';
import { Card, CardHeader, CardTitle, CardDescription } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { ScrollText, Plus, RefreshCw, Send, Terminal } from 'lucide-react';

export default function LogsPage() {
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [logs, setLogs] = useState<LogItem[]>([
    {
      id: 'log-seed-01',
      source: 'wazuh-betim-core',
      tenant_id: 'betim',
      timestamp: new Date(Date.now() - 1000 * 60 * 12).toISOString(),
      raw_data: { event: 'AUTHENTICATION_SUCCESS', user: 'analista.seguranca', ip: '10.0.4.15' },
    },
    {
      id: 'log-seed-02',
      source: 'firewall-fortinet-01',
      tenant_id: 'betim-saude',
      timestamp: new Date(Date.now() - 1000 * 60 * 45).toISOString(),
      raw_data: { event: 'DENY_PORT_SCAN', target_port: 445, src_ip: '185.220.101.5' },
    },
  ]);

  const handleIngestSuccess = (newLog: LogItem) => {
    setLogs((prev) => [newLog, ...prev]);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-[#121824] p-6 rounded-xl border border-[#1e293b]">
        <div>
          <div className="flex items-center gap-2 text-cyan-400 font-semibold text-xs uppercase tracking-wider mb-1">
            <ScrollText className="w-4 h-4" /> Auditoria de Eventos
          </div>
          <h1 className="text-xl font-bold text-slate-100">Central de Logs & Ingestão</h1>
          <p className="text-xs text-slate-400 mt-1">
            Simulador de eventos e auditoria de mensagens transmitidas ao broker Redpanda/Kafka pelo IngestLogCommand.
          </p>
        </div>

        <Button variant="primary" onClick={() => setIsModalOpen(true)} className="gap-2">
          <Send className="w-4 h-4" /> Ingerir Log de Teste
        </Button>
      </div>

      {/* Main List */}
      <Card>
        <CardHeader>
          <div>
            <CardTitle>Logs Ingeridos (EventBus Queue)</CardTitle>
            <CardDescription>Auditoria contínua de eventos de segurança registrados</CardDescription>
          </div>
          <div className="flex items-center gap-2 font-mono text-xs text-cyan-400 bg-cyan-950/40 px-3 py-1.5 rounded-lg border border-cyan-800/40">
            <Terminal className="w-3.5 h-3.5" /> Total Ingeridos: {logs.length}
          </div>
        </CardHeader>

        <LogList logs={logs} isLoading={false} />
      </Card>

      <LogIngestModal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        onSuccess={handleIngestSuccess}
      />
    </div>
  );
}
