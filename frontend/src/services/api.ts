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
  timeoutMs = 120_000,
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

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  let res: Response;
  try {
    res = await fetch(url, {
      ...options,
      headers,
      signal: controller.signal,
    });
  } catch (err) {
    clearTimeout(timer);
    if (err instanceof DOMException && err.name === 'AbortError') {
      throw new ApiError(`Request timed out after ${timeoutMs}ms: ${path}`, 0, null);
    }
    throw err;
  }
  clearTimeout(timer);

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

function parseDownloadFilename(header: string | null): string | null {
  if (!header) return null;
  const utf8Match = header.match(/filename\*=UTF-8''([^;]+)/i);
  if (utf8Match?.[1]) {
    return decodeURIComponent(utf8Match[1]);
  }
  const plainMatch = header.match(/filename="([^"]+)"/i) ?? header.match(/filename=([^;]+)/i);
  return plainMatch?.[1]?.trim() ?? null;
}

async function download(
  path: string,
  options: RequestInit = {},
  timeoutMs = 120_000,
): Promise<{ blob: Blob; filename: string | null }> {
  const url = `${BASE_URL}${path}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  let res: Response;
  try {
    res = await fetch(url, {
      ...options,
      signal: controller.signal,
    });
  } catch (err) {
    clearTimeout(timer);
    if (err instanceof DOMException && err.name === 'AbortError') {
      throw new ApiError(`Request timed out after ${timeoutMs}ms: ${path}`, 0, null);
    }
    throw err;
  }
  clearTimeout(timer);

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

  return {
    blob: await res.blob(),
    filename: parseDownloadFilename(res.headers.get('Content-Disposition')),
  };
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

export async function deleteProject(projectId: string): Promise<void> {
  return request<void>(`/projects/${projectId}`, { method: 'DELETE' });
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

export async function deleteSample(sampleId: string): Promise<void> {
  return request<void>(`/samples/${sampleId}`, { method: 'DELETE' });
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
  const resp = await request<{ strings: StringEntry[] } | StringEntry[]>(
    `/samples/${sampleId}/strings`,
  );
  // Backend wraps the array in { sample_id, count, strings }.
  // Unwrap it so callers always receive a plain array.
  if (Array.isArray(resp)) return resp;
  if (resp && typeof resp === 'object' && 'strings' in resp) {
    return (resp as { strings: StringEntry[] }).strings;
  }
  return [];
}

export async function getIOCs(sampleId: string): Promise<IOC[]> {
  const resp = await request<{ iocs: IOC[] } | IOC[]>(
    `/samples/${sampleId}/iocs`,
  );
  if (Array.isArray(resp)) return resp;
  if (resp && typeof resp === 'object' && 'iocs' in resp) {
    return (resp as { iocs: IOC[] }).iocs;
  }
  return [];
}

export async function getFindings(sampleId: string): Promise<Finding[]> {
  const resp = await request<{ findings: Finding[] } | Finding[]>(
    `/samples/${sampleId}/findings`,
  );
  if (Array.isArray(resp)) return resp;
  if (resp && typeof resp === 'object' && 'findings' in resp) {
    return (resp as { findings: Finding[] }).findings;
  }
  return [];
}

export async function getTransforms(
  sampleId: string,
): Promise<TransformRecord[]> {
  const resp = await request<{ transforms: TransformRecord[] } | TransformRecord[]>(
    `/samples/${sampleId}/transforms`,
  );
  if (Array.isArray(resp)) return resp;
  if (resp && typeof resp === 'object' && 'transforms' in resp) {
    return (resp as { transforms: TransformRecord[] }).transforms;
  }
  return [];
}

export async function getAnalysisState(
  sampleId: string,
): Promise<AnalysisState | null> {
  try {
    const data = await request<{
      sample_id: string;
      count: number;
      iterations: { id: string; iteration_number: number; state_json: AnalysisState | string; created_at: string | null }[];
    }>(`/samples/${sampleId}/iterations`);
    if (!data.iterations || data.iterations.length === 0) return null;
    // Return the latest iteration's state
    const latest = data.iterations[data.iterations.length - 1];
    if (!latest.state_json) return null;
    // state_json may be a serialised JSON string from the DB — parse it.
    const state: AnalysisState =
      typeof latest.state_json === 'string'
        ? JSON.parse(latest.state_json)
        : latest.state_json;
    return state;
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
//  AI Summary
// ════════════════════════════════════════════════════════════════════════

export async function generateSummary(sampleId: string): Promise<string> {
  const resp = await request<{ summary: string }>(`/samples/${sampleId}/summary`, {
    method: 'POST',
  });
  return resp.summary;
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

export async function exportDeobfuscated(
  sampleId: string,
): Promise<{ blob: Blob; filename: string | null }> {
  return download(`/samples/${sampleId}/export/deobfuscated`);
}

// ════════════════════════════════════════════════════════════════════════
//  WebSocket
// ════════════════════════════════════════════════════════════════════════

export function getAnalysisWsUrl(sampleId: string): string {
  const loc = window.location;
  const wsProtocol = loc.protocol === 'https:' ? 'wss:' : 'ws:';
  // In dev, proxy is configured in vite.config to route /api to backend
  return `${wsProtocol}//${loc.host}/api/ws/analysis/${sampleId}`;
}

// ════════════════════════════════════════════════════════════════════════
//  Iteration snapshot (for transform code viewer)
// ════════════════════════════════════════════════════════════════════════

export interface IterationSnapshot {
  id: string;
  iteration_number: number;
  state_json: AnalysisState;
  created_at: string | null;
}

export async function getIterations(sampleId: string): Promise<IterationSnapshot[]> {
  const data = await request<{
    sample_id: string;
    count: number;
    iterations: IterationSnapshot[];
  }>(`/samples/${sampleId}/iterations`);
  return data.iterations;
}

export { ApiError };
