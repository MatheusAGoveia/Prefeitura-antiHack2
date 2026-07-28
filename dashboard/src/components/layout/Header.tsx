'use client';

import React, { useEffect, useState } from 'react';
import { checkHealth, checkReady } from '@/lib/api/system';
import { fetchToken, saveToken } from '@/lib/api/auth';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { ShieldCheck, Key, Server, RefreshCw } from 'lucide-react';

export function Header() {
  const [health, setHealth] = useState<'online' | 'offline' | 'checking'>('checking');
  const [ready, setReady] = useState<boolean>(false);
  const [isAuthenticating, setIsAuthenticating] = useState<boolean>(false);

  const verifyBackendStatus = async () => {
    setHealth('checking');
    try {
      const h = await checkHealth();
      setHealth(h.status === 'ok' ? 'online' : 'offline');
      const r = await checkReady();
      setReady(r.status === 'ready');
    } catch {
      setHealth('offline');
      setReady(false);
    }
  };

  useEffect(() => {
    verifyBackendStatus();
    // Pre-fetch access token for developer session
    fetchToken().then((res) => {
      saveToken(res.access_token);
    }).catch(() => null);
  }, []);

  const handleSimulateLogin = async () => {
    setIsAuthenticating(true);
    try {
      const res = await fetchToken();
      saveToken(res.access_token);
      alert('Token JWT gerado e salvo no localStorage com sucesso!');
    } catch (err) {
      alert('Erro ao obter token do backend. Verifique se a API está rodando na porta 8000.');
    } finally {
      setIsAuthenticating(false);
    }
  };

  return (
    <header className="bg-[#0c1018] border-b border-[#1e293b] px-6 py-3.5 flex items-center justify-between sticky top-0 z-10 backdrop-blur-md bg-opacity-90">
      <div className="flex items-center gap-4">
        <h2 className="text-sm font-semibold text-slate-200 uppercase tracking-wider">
          Painel Operacional de Segurança
        </h2>
        <div className="flex items-center gap-2">
          {health === 'online' ? (
            <Badge variant="success" className="gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping" />
              API Core Online
            </Badge>
          ) : health === 'offline' ? (
            <Badge variant="danger" className="gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-rose-400" />
              API Offline
            </Badge>
          ) : (
            <Badge variant="secondary" className="gap-1">
              Verificando...
            </Badge>
          )}

          {ready && (
            <Badge variant="info" className="gap-1">
              <Server className="w-3 h-3" /> DB & Kafka Ready
            </Badge>
          )}
        </div>
      </div>

      <div className="flex items-center gap-3">
        <Button variant="ghost" size="sm" onClick={verifyBackendStatus} title="Atualizar Status">
          <RefreshCw className="w-3.5 h-3.5 text-slate-400" />
        </Button>

        <Button
          variant="outline"
          size="sm"
          onClick={handleSimulateLogin}
          disabled={isAuthenticating}
          className="gap-2"
        >
          <Key className="w-3.5 h-3.5 text-cyan-400" />
          {isAuthenticating ? 'Autenticando...' : 'Obter JWT Token'}
        </Button>

        <div className="flex items-center gap-2 pl-3 border-l border-[#1e293b] text-xs">
          <div className="w-8 h-8 rounded-full bg-cyan-950 border border-cyan-800 text-cyan-300 flex items-center justify-center font-semibold shadow-md">
            SA
          </div>
          <div>
            <p className="font-semibold text-slate-200 text-xs">admin-01</p>
            <p className="text-[10px] text-cyan-400 font-mono">system_admin</p>
          </div>
        </div>
      </div>
    </header>
  );
}
