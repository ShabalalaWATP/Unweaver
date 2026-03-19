import type {
  Project,
  ProjectCreate,
  Sample,
  SampleDetail,
  SampleCreate,
  StringEntry,
  Finding,
  IOC,
  TransformRecord,
  AnalysisStatus,
  ProviderSettings,
  ProviderSettingsCreate,
  AnalysisState,
} from '@/types';

// ════════════════════════════════════════════════════════════════════════
//  Base configuration
// ════════════════════════════════════════════════════════════════════════

const BASE_URL = import.meta.env.VITE_API_BASE_URL ?? '/api';

class ApiError extends Error {
  status: number;
  body: unknown;

  constructor(message: string, status: number, body: unknown) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.body = body;
  }
}

async function request<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const url = `${BASE_URL}${path}`;
  const headers: Record<string, string> = {
    ...(options.headers as Record<string, string> | undefined),
  };

  if (
    options.body &&
    typeof options.body === 'string' &&
    !headers['Content-Type']
  ) {
    headers['Content-Type'] = 'application/json';
  }

  const res = await fetch(url, { ...options, headers });

  if (!res.ok) {
    let body: unknown;
    try {
      body = await res.json();
    } catch {
      body = await res.text();
    }
    throw new ApiError(
      `API ${options.method ?? 'GET'} ${path} failed (${res.status})`,
      res.status,
      body,
    );
  }

  if (res.status === 204) {
    return undefined as T;
  }

  const contentType = res.headers.get('Content-Type') ?? '';
  if (contentType.includes('application/json')) {
    return res.json() as Promise<T>;
  }
  return res.text() as unknown as T;
}

// ════════════════════════════════════════════════════════════════════════
//  Projects
// ════════════════════════════════════════════════════════════════════════

export async function listProjects(): Promise<Project[]> {
  return request<Project[]>('/projects');
}

export async function createProject(data: ProjectCreate): Promise<Project> {
  return request<Project>('/projects', {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

// ════════════════════════════════════════════════════════════════════════
//  Samples
// ════════════════════════════════════════════════════════════════════════

export async function listSamples(projectId: string): Promise<Sample[]> {
  return request<Sample[]>(`/projects/${projectId}/samples`);
}

export async function getSample(sampleId: string): Promise<SampleDetail> {
  return request<SampleDetail>(`/samples/${sampleId}`);
}

export async function pasteSample(data: SampleCreate): Promise<Sample> {
  const { project_id, ...body } = data;
  return request<Sample>(`/projects/${project_id}/samples/paste`, {
    method: 'POST',
    body: JSON.stringify(body),
  });
}

export async function uploadSample(
  projectId: string,
  file: File,
  language?: string,
): Promise<Sample> {
  const formData = new FormData();
  formData.append('file', file);
  if (language) {
    formData.append('language', language);
  }
  return request<Sample>(`/projects/${projectId}/samples/upload`, {
    method: 'POST',
    body: formData,
  });
}

// ════════════════════════════════════════════════════════════════════════
//  Sample content
// ════════════════════════════════════════════════════════════════════════

export async function getOriginal(sampleId: string): Promise<string> {
  return request<string>(`/samples/${sampleId}/original`);
}

export async function getRecovered(sampleId: string): Promise<string> {
  return request<string>(`/samples/${sampleId}/recovered`);
}

export async function getDiff(
  sampleId: string,
): Promise<{ original: string; recovered: string }> {
  return request<{ original: string; recovered: string }>(
    `/samples/${sampleId}/diff`,
  );
}

export async function getStrings(sampleId: string): Promise<StringEntry[]> {
  return request<StringEntry[]>(`/samples/${sampleId}/strings`);
}

export async function getIOCs(sampleId: string): Promise<IOC[]> {
  return request<IOC[]>(`/samples/${sampleId}/iocs`);
}

export async function getFindings(sampleId: string): Promise<Finding[]> {
  return request<Finding[]>(`/samples/${sampleId}/findings`);
}

export async function getTransforms(
  sampleId: string,
): Promise<TransformRecord[]> {
  return request<TransformRecord[]>(`/samples/${sampleId}/transforms`);
}

export async function getAnalysisState(
  sampleId: string,
): Promise<AnalysisState | null> {
  try {
    const data = await request<{
      sample_id: string;
      count: number;
      iterations: { id: string; iteration_number: number; state_json: AnalysisState; created_at: string | null }[];
    }>(`/samples/${sampleId}/iterations`);
    if (data.iterations.length === 0) return null;
    // Return the latest iteration's state
    const latest = data.iterations[data.iterations.length - 1];
    return latest.state_json ?? null;
  } catch {
    return null;
  }
}

// ════════════════════════════════════════════════════════════════════════
//  Analyst notes
// ════════════════════════════════════════════════════════════════════════

export async function saveNotes(
  sampleId: string,
  notes: string,
): Promise<void> {
  return request<void>(`/samples/${sampleId}/notes`, {
    method: 'PUT',
    body: JSON.stringify({ sample_id: sampleId, notes }),
  });
}

// ════════════════════════════════════════════════════════════════════════
//  Analysis control
// ════════════════════════════════════════════════════════════════════════

export async function startAnalysis(sampleId: string): Promise<void> {
  return request<void>(`/samples/${sampleId}/analyze`, {
    method: 'POST',
  });
}

export async function getAnalysisStatus(
  sampleId: string,
): Promise<AnalysisStatus> {
  return request<AnalysisStatus>(`/samples/${sampleId}/analysis/status`);
}

export async function stopAnalysis(sampleId: string): Promise<void> {
  return request<void>(`/samples/${sampleId}/analysis/stop`, {
    method: 'POST',
  });
}

// ════════════════════════════════════════════════════════════════════════
//  Provider settings
// ════════════════════════════════════════════════════════════════════════

export async function getProviders(): Promise<ProviderSettings[]> {
  return request<ProviderSettings[]>('/providers');
}

export async function createProvider(
  data: ProviderSettingsCreate,
): Promise<ProviderSettings> {
  return request<ProviderSettings>('/providers', {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

export async function updateProvider(
  id: string,
  data: ProviderSettingsCreate,
): Promise<ProviderSettings> {
  return request<ProviderSettings>(`/providers/${id}`, {
    method: 'PUT',
    body: JSON.stringify(data),
  });
}

export async function deleteProvider(id: string): Promise<void> {
  return request<void>(`/providers/${id}`, { method: 'DELETE' });
}

export async function testProvider(
  id: string,
): Promise<{ success: boolean; message: string }> {
  return request<{ success: boolean; message: string }>(
    `/providers/${id}/test`,
    { method: 'POST' },
  );
}

// ════════════════════════════════════════════════════════════════════════
//  Export
// ════════════════════════════════════════════════════════════════════════

export async function exportMarkdown(sampleId: string): Promise<string> {
  return request<string>(`/samples/${sampleId}/export/markdown`);
}

export async function exportJSON(sampleId: string): Promise<unknown> {
  return request<unknown>(`/samples/${sampleId}/export/json`);
}

export { ApiError };
