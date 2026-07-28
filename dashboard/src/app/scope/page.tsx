'use client';

import React, { useState } from 'react';
import { checkScope } from '@/lib/api/system';
import { ScopeCheckResponse } from '@/types';
import { Card, CardHeader, CardTitle, CardDescription } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { Badge } from '@/components/ui/Badge';
import { ShieldAlert, ShieldCheck, Search, Globe, AlertTriangle } from 'lucide-react';

export default function ScopeSafetyPage() {
  const [ipInput, setIpInput] = useState('10.0.1.50');
  const [result, setResult] = useState<ScopeCheckResponse | null>(null);
  const [isChecking, setIsChecking] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const handleCheck = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);
    setResult(null);

    if (!ipInput.trim()) return;

    setIsChecking(true);
    try {
      const res = await checkScope({ target_ip: ipInput.trim() });
      setResult(res);
    } catch (err: any) {
      setErrorMessage('Erro ao comunicar com a API do Core Platform. Verifique a execução do backend.');
    } finally {
      setIsChecking(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-[#121824] p-6 rounded-xl border border-[#1e293b]">
        <div>
          <div className="flex items-center gap-2 text-cyan-400 font-semibold text-xs uppercase tracking-wider mb-1">
            <ShieldAlert className="w-4 h-4" /> Módulo de Proteção de Escopo
          </div>
          <h1 className="text-xl font-bold text-slate-100">ScopeSafety Protection Check (INV-005)</h1>
          <p className="text-xs text-slate-400 mt-1">
            Validador em tempo real de alvos IP contra a lista de sub-redes autorizadas da prefeitura (ex: 10.0.0.0/8, 177.105.0.0/16).
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Form Card */}
        <Card>
          <CardHeader>
            <div>
              <CardTitle>Validar IP / Sub-rede</CardTitle>
              <CardDescription>Insira um endereço IPv4 para verificar autorização no escopo governamental</CardDescription>
            </div>
            <Globe className="w-5 h-5 text-cyan-400" />
          </CardHeader>

          <form onSubmit={handleCheck} className="space-y-4">
            <Input
              label="Endereço IP Alvo"
              placeholder="Ex: 10.0.1.50 ou 8.8.8.8"
              value={ipInput}
              onChange={(e) => setIpInput(e.target.value)}
              required
            />

            <div className="flex justify-between items-center pt-2">
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={() => setIpInput('10.0.4.15')}
                  className="text-[11px] font-mono bg-slate-800 text-cyan-300 px-2 py-1 rounded hover:bg-slate-700"
                >
                  Exemplo Autorizado (10.0.4.15)
                </button>
                <button
                  type="button"
                  onClick={() => setIpInput('8.8.8.8')}
                  className="text-[11px] font-mono bg-slate-800 text-rose-300 px-2 py-1 rounded hover:bg-slate-700"
                >
                  Exemplo Bloqueado (8.8.8.8)
                </button>
              </div>

              <Button type="submit" variant="primary" disabled={isChecking} className="gap-2">
                <Search className="w-4 h-4" />
                {isChecking ? 'Verificando...' : 'Verificar Escopo'}
              </Button>
            </div>
          </form>
        </Card>

        {/* Result Card */}
        <Card>
          <CardHeader>
            <div>
              <CardTitle>Resultado da Validação</CardTitle>
              <CardDescription>Resposta emitida pelo ScopeSafety Engine</CardDescription>
            </div>
          </CardHeader>

          {errorMessage ? (
            <div className="p-4 bg-rose-950/60 border border-rose-800/80 rounded-lg text-rose-300 text-xs">
              {errorMessage}
            </div>
          ) : !result ? (
            <div className="py-12 text-center text-slate-500 text-xs">
              Insira um IP ao lado e clique em "Verificar Escopo" para obter a decisão de autorização.
            </div>
          ) : (
            <div className="space-y-4">
              <div
                className={`p-5 rounded-xl border flex items-center gap-4 ${
                  result.is_allowed
                    ? 'bg-emerald-950/40 border-emerald-800/80 text-emerald-300'
                    : 'bg-rose-950/40 border-rose-800/80 text-rose-300'
                }`}
              >
                {result.is_allowed ? (
                  <ShieldCheck className="w-10 h-10 text-emerald-400 shrink-0" />
                ) : (
                  <AlertTriangle className="w-10 h-10 text-rose-400 shrink-0" />
                )}
                <div>
                  <h3 className="font-bold text-base uppercase tracking-wider">
                    {result.status === 'AUTHORIZED' ? 'Alvo Autorizado' : 'Violação de Escopo'}
                  </h3>
                  <p className="text-xs mt-0.5 opacity-90">
                    {result.is_allowed
                      ? `O IP ${result.target_ip} pertence à sub-rede aprovada para operações da prefeitura.`
                      : `O IP ${result.target_ip} ESTÁ FORA do escopo governamental configurado.`}
                  </p>
                </div>
              </div>

              <div className="p-3 bg-[#0a0d14] rounded-lg border border-[#1e293b] text-xs font-mono space-y-1">
                <span className="text-slate-500">JSON Response Payload:</span>
                <pre className="text-cyan-300 overflow-x-auto">{JSON.stringify(result, null, 2)}</pre>
              </div>
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
