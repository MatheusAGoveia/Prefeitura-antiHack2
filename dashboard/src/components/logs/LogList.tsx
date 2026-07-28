'use client';

import React, { useState } from 'react';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/Table';
import { Badge } from '@/components/ui/Badge';
import { ScrollText, Clock, Server, FileText } from 'lucide-react';

export interface LogItem {
  id: string;
  source: string;
  tenant_id: string;
  timestamp: string;
  raw_data: Record<string, any>;
  severity?: 'INFO' | 'WARN' | 'CRITICAL';
}

interface LogListProps {
  logs: LogItem[];
  isLoading: boolean;
}

export function LogList({ logs, isLoading }: LogListProps) {
  const [selectedLog, setSelectedLog] = useState<LogItem | null>(null);

  if (isLoading) {
    return (
      <div className="p-8 text-center text-slate-400 bg-[#121824] rounded-xl border border-[#1e293b]">
        <div className="animate-spin inline-block w-6 h-6 border-2 border-cyan-500 border-t-transparent rounded-full mb-2"></div>
        <p className="text-sm">Carregando logs auditados...</p>
      </div>
    );
  }

  if (!logs || logs.length === 0) {
    return (
      <div className="p-12 text-center bg-[#121824] rounded-xl border border-[#1e293b] space-y-3">
        <ScrollText className="w-10 h-10 text-slate-600 mx-auto" />
        <h3 className="text-base font-semibold text-slate-300">Nenhum evento registrado</h3>
        <p className="text-xs text-slate-500 max-w-sm mx-auto">
          Utilize o botão "Ingerir Log de Teste" para enviar novos eventos de auditoria para o EventBus (Redpanda/Kafka).
        </p>
      </div>
    );
  }

  return (
    <>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Timestamp</TableHead>
            <TableHead>Fonte (Source)</TableHead>
            <TableHead>Tenant ID</TableHead>
            <TableHead>Dados do Evento (Payload JSON)</TableHead>
            <TableHead>Ações</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {logs.map((log) => (
            <TableRow key={log.id}>
              <TableCell className="text-xs text-slate-400 font-mono">
                <div className="flex items-center gap-1.5">
                  <Clock className="w-3.5 h-3.5 text-slate-500" />
                  <span>{new Date(log.timestamp).toLocaleString('pt-BR')}</span>
                </div>
              </TableCell>
              <TableCell>
                <Badge variant="info" className="gap-1 font-mono">
                  <Server className="w-3 h-3" />
                  {log.source}
                </Badge>
              </TableCell>
              <TableCell className="font-mono text-xs text-cyan-400">{log.tenant_id}</TableCell>
              <TableCell className="font-mono text-xs text-slate-300 max-w-xs truncate">
                {JSON.stringify(log.raw_data)}
              </TableCell>
              <TableCell>
                <button
                  onClick={() => setSelectedLog(log)}
                  className="text-xs font-semibold text-cyan-400 hover:text-cyan-300 underline flex items-center gap-1"
                >
                  <FileText className="w-3.5 h-3.5" /> Detalhes
                </button>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>

      {/* Detail Modal */}
      {selectedLog && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="bg-[#121824] border border-[#1e293b] rounded-xl w-full max-w-xl p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-[#1e293b] pb-3">
              <h3 className="font-semibold text-slate-100 flex items-center gap-2 text-base">
                <ScrollText className="w-5 h-5 text-cyan-400" /> Detalhes do Log Registrado
              </h3>
              <button onClick={() => setSelectedLog(null)} className="text-slate-400 hover:text-slate-200">
                ✕
              </button>
            </div>
            <div className="space-y-3 text-xs">
              <div className="grid grid-cols-2 gap-2 bg-[#0a0d14] p-3 rounded-lg border border-[#1e293b]">
                <div>
                  <span className="text-slate-500 block">ID do Evento:</span>
                  <span className="font-mono text-slate-200">{selectedLog.id}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Fonte Ingestora:</span>
                  <span className="font-mono text-cyan-400">{selectedLog.source}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Tenant:</span>
                  <span className="font-mono text-slate-200">{selectedLog.tenant_id}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Timestamp UTC:</span>
                  <span className="font-mono text-slate-200">{selectedLog.timestamp}</span>
                </div>
              </div>

              <div>
                <span className="text-slate-400 font-semibold block mb-1.5 uppercase text-[10px]">
                  Raw Payload JSON (Audit Log)
                </span>
                <pre className="bg-[#07090e] p-4 rounded-lg border border-[#1e293b] text-cyan-300 font-mono text-xs overflow-x-auto">
                  {JSON.stringify(selectedLog.raw_data, null, 2)}
                </pre>
              </div>
            </div>
            <div className="flex justify-end pt-2">
              <button
                onClick={() => setSelectedLog(null)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-semibold"
              >
                Fechar
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
