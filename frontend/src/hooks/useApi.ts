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

  return {
    projects: state.data ?? [],
    loading: state.loading,
    error: state.error,
    refetch: state.refetch,
    create,
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

  return {
    samples: state.data ?? [],
    loading: state.loading,
    error: state.error,
    refetch: state.refetch,
    upload,
    paste,
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
//  Analysis status with polling
// ════════════════════════════════════════════════════════════════════════

export function useAnalysisStatus(sampleId: string | null, active = false) {
  const [status, setStatus] = useState<AnalysisStatus | null>(null);
  const mountedRef = useRef(true);

  useEffect(() => {
    mountedRef.current = true;
    if (!sampleId || !active) {
      setStatus(null);
      return;
    }

    let timer: ReturnType<typeof setTimeout>;
    let consecutiveErrors = 0;
    const BASE_INTERVAL = 2000;
    const MAX_INTERVAL = 30000;
    const MAX_CONSECUTIVE_ERRORS = 30;

    const poll = async () => {
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
      if (mountedRef.current) {
        // Exponential backoff on errors, base interval on success
        const delay = consecutiveErrors > 0
          ? Math.min(BASE_INTERVAL * Math.pow(1.5, consecutiveErrors), MAX_INTERVAL)
          : BASE_INTERVAL;
        timer = setTimeout(poll, delay);
      }
    };

    poll();

    return () => {
      mountedRef.current = false;
      clearTimeout(timer);
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

export { useAsync };
