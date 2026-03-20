import { useState, useEffect, useCallback, useRef } from 'react';
import type {
  Project,
  Sample,
  SampleDetail,
  AnalysisStatus,
  ProviderSettings,
  ProviderSettingsCreate,
} from '@/types';
import * as api from '@/services/api';

// ════════════════════════════════════════════════════════════════════════
//  Generic async hook
// ════════════════════════════════════════════════════════════════════════

interface AsyncState<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
  refetch: () => void;
}

function useAsync<T>(
  fn: () => Promise<T>,
  deps: unknown[] = [],
  enabled = true,
): AsyncState<T> {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const mountedRef = useRef(true);

  const execute = useCallback(async () => {
    if (!enabled) return;
    setLoading(true);
    setError(null);
    try {
      const result = await fn();
      if (mountedRef.current) {
        setData(result);
      }
    } catch (err) {
      if (mountedRef.current) {
        setError(err instanceof Error ? err.message : String(err));
      }
    } finally {
      if (mountedRef.current) {
        setLoading(false);
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  useEffect(() => {
    mountedRef.current = true;
    execute();
    return () => {
      mountedRef.current = false;
    };
  }, [execute]);

  return { data, loading, error, refetch: execute };
}

// ════════════════════════════════════════════════════════════════════════
//  Projects
// ════════════════════════════════════════════════════════════════════════

export function useProjects() {
  const state = useAsync<Project[]>(() => api.listProjects(), []);

  const create = useCallback(
    async (name: string, description?: string) => {
      const project = await api.createProject({ name, description });
      state.refetch();
      return project;
    },
    [state],
  );

  const remove = useCallback(
    async (id: string) => {
      await api.deleteProject(id);
      state.refetch();
    },
    [state],
  );

  return {
    projects: state.data ?? [],
    loading: state.loading,
    error: state.error,
    refetch: state.refetch,
    create,
    remove,
  };
}

// ════════════════════════════════════════════════════════════════════════
//  Samples for a project
// ════════════════════════════════════════════════════════════════════════

export function useSamples(projectId: string | null) {
  const state = useAsync<Sample[]>(
    () => (projectId ? api.listSamples(projectId) : Promise.resolve([])),
    [projectId],
    !!projectId,
  );

  const upload = useCallback(
    async (file: File, language?: string) => {
      if (!projectId) throw new Error('No project selected');
      const sample = await api.uploadSample(projectId, file, language);
      state.refetch();
      return sample;
    },
    [projectId, state],
  );

  const paste = useCallback(
    async (text: string, filename?: string, language?: string) => {
      if (!projectId) throw new Error('No project selected');
      const sample = await api.pasteSample({
        project_id: projectId,
        original_text: text,
        filename: filename || 'paste.txt',
        language: language || undefined,
      });
      state.refetch();
      return sample;
    },
    [projectId, state],
  );

  const remove = useCallback(
    async (id: string) => {
      await api.deleteSample(id);
      state.refetch();
    },
    [state],
  );

  return {
    samples: state.data ?? [],
    loading: state.loading,
    error: state.error,
    refetch: state.refetch,
    upload,
    paste,
    remove,
  };
}

// ════════════════════════════════════════════════════════════════════════
//  Single sample detail
// ════════════════════════════════════════════════════════════════════════

export function useSample(sampleId: string | null) {
  const state = useAsync<SampleDetail>(
    () => (sampleId ? api.getSample(sampleId) : Promise.resolve(null as unknown as SampleDetail)),
    [sampleId],
    !!sampleId,
  );

  return {
    sample: state.data,
    loading: state.loading,
    error: state.error,
    refetch: state.refetch,
  };
}

// ════════════════════════════════════════════════════════════════════════
//  Analysis status — WebSocket with polling fallback
// ════════════════════════════════════════════════════════════════════════

export function useAnalysisStatus(sampleId: string | null, active = false) {
  const [status, setStatus] = useState<AnalysisStatus | null>(null);
  const mountedRef = useRef(true);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    mountedRef.current = true;
    if (!sampleId || !active) {
      setStatus(null);
      return;
    }

    let timer: ReturnType<typeof setTimeout>;
    let consecutiveErrors = 0;
    let usingWs = false;
    const BASE_INTERVAL = 2000;
    const MAX_INTERVAL = 30000;
    const MAX_CONSECUTIVE_ERRORS = 30;

    // ── Try WebSocket first ────────────────────────────────────
    const tryWebSocket = () => {
      try {
        const wsUrl = api.getAnalysisWsUrl(sampleId);
        const ws = new WebSocket(wsUrl);
        wsRef.current = ws;

        ws.onopen = () => {
          usingWs = true;
        };

        ws.onmessage = (evt) => {
          try {
            const data = JSON.parse(evt.data) as AnalysisStatus;
            if (mountedRef.current) {
              setStatus(data);
              // Stop if terminal
              if (data.status !== 'running' && data.status !== 'pending') {
                ws.close();
              }
            }
          } catch {
            // ignore parse errors
          }
        };

        ws.onerror = () => {
          // WebSocket failed — fall back to polling
          usingWs = false;
          ws.close();
          wsRef.current = null;
          startPolling();
        };

        ws.onclose = () => {
          wsRef.current = null;
          // If we were using WS and it closed unexpectedly, fall back to polling
          if (usingWs && mountedRef.current) {
            usingWs = false;
            startPolling();
          }
        };
      } catch {
        // WebSocket construction failed, fall back
        startPolling();
      }
    };

    // ── Polling fallback ───────────────────────────────────────
    const poll = async () => {
      if (usingWs) return; // WebSocket is handling it
      try {
        const s = await api.getAnalysisStatus(sampleId);
        consecutiveErrors = 0;
        if (mountedRef.current) {
          setStatus(s);
          if (s.status !== 'running' && s.status !== 'pending') {
            return; // stop polling
          }
        }
      } catch (err) {
        consecutiveErrors++;
        if (consecutiveErrors <= 3) {
          console.warn('Analysis status poll error:', err);
        }
        if (consecutiveErrors >= MAX_CONSECUTIVE_ERRORS) {
          console.error('Analysis status polling stopped after too many errors');
          return; // stop polling
        }
      }
      if (mountedRef.current && !usingWs) {
        const delay = consecutiveErrors > 0
          ? Math.min(BASE_INTERVAL * Math.pow(1.5, consecutiveErrors), MAX_INTERVAL)
          : BASE_INTERVAL;
        timer = setTimeout(poll, delay);
      }
    };

    const startPolling = () => {
      if (!mountedRef.current) return;
      poll();
    };

    // Start with WebSocket attempt
    tryWebSocket();

    // Also start polling as a safety net (will stop if WS connects)
    // Give WS 500ms to connect before starting polling
    const pollDelayTimer = setTimeout(() => {
      if (!usingWs && mountedRef.current) {
        startPolling();
      }
    }, 500);

    return () => {
      mountedRef.current = false;
      clearTimeout(timer);
      clearTimeout(pollDelayTimer);
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
    };
  }, [sampleId, active]);

  return status;
}

// ════════════════════════════════════════════════════════════════════════
//  Providers
// ════════════════════════════════════════════════════════════════════════

export function useProviders() {
  const state = useAsync<ProviderSettings[]>(() => api.getProviders(), []);

  const create = useCallback(
    async (data: ProviderSettingsCreate) => {
      const provider = await api.createProvider(data);
      state.refetch();
      return provider;
    },
    [state],
  );

  const update = useCallback(
    async (id: string, data: ProviderSettingsCreate) => {
      const provider = await api.updateProvider(id, data);
      state.refetch();
      return provider;
    },
    [state],
  );

  const remove = useCallback(
    async (id: string) => {
      await api.deleteProvider(id);
      state.refetch();
    },
    [state],
  );

  const test = useCallback(async (id: string) => {
    return api.testProvider(id);
  }, []);

  return {
    providers: state.data ?? [],
    loading: state.loading,
    error: state.error,
    refetch: state.refetch,
    create,
    update,
    remove,
    test,
  };
}

// ════════════════════════════════════════════════════════════════════════
//  localStorage persistence helper
// ════════════════════════════════════════════════════════════════════════

const STORAGE_KEY = 'unweaver-ui-state';

interface PersistedState {
  selectedProjectId: string | null;
  selectedSampleId: string | null;
  activeTab: string | null;
  view: string | null;
}

export function loadPersistedState(): PersistedState {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return { selectedProjectId: null, selectedSampleId: null, activeTab: null, view: null };
    return JSON.parse(raw);
  } catch {
    return { selectedProjectId: null, selectedSampleId: null, activeTab: null, view: null };
  }
}

export function savePersistedState(state: Partial<PersistedState>) {
  try {
    const existing = loadPersistedState();
    localStorage.setItem(STORAGE_KEY, JSON.stringify({ ...existing, ...state }));
  } catch {
    // ignore storage errors
  }
}

export { useAsync };
