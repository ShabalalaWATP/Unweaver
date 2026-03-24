const WORKSPACE_BUNDLE_HEADER = 'UNWEAVER_WORKSPACE_BUNDLE v1';
const FILE_MARKER_RE = /<<<FILE path="([^"]+)" language="([^"]+)" priority="([^"]+)" size=(\d+)>>>\n([\s\S]*?)\n<<<END FILE>>>/g;

export interface WorkspaceBundleFile {
  path: string;
  language: string;
  priority: string[];
  size_bytes: number;
  text: string;
}

export interface WorkspaceBundleData {
  archive_name: string;
  included_files: number;
  omitted_files: number;
  languages: string;
  entry_points: string[];
  suspicious_files: string[];
  manifest_files: string[];
  root_dirs: string[];
  prioritized_paths: string[];
  bundle_note: string;
  files: WorkspaceBundleFile[];
}

function splitManifestValue(value: string | undefined): string[] {
  if (!value || value === 'none') return [];
  return value
    .split('|')
    .map((item) => item.trim())
    .filter(Boolean);
}

function parseManifestInt(value: string | undefined): number {
  const parsed = Number.parseInt(value ?? '', 10);
  return Number.isFinite(parsed) ? parsed : 0;
}

export function parseWorkspaceBundle(bundleText: string | null | undefined): WorkspaceBundleData | null {
  if (!bundleText || !bundleText.startsWith(WORKSPACE_BUNDLE_HEADER)) {
    return null;
  }

  const firstFileIndex = bundleText.indexOf('<<<FILE ');
  const headerText = firstFileIndex >= 0 ? bundleText.slice(0, firstFileIndex) : bundleText;
  const manifest: Record<string, string> = {};

  for (const line of headerText.split('\n').slice(1)) {
    const separatorIndex = line.indexOf(':');
    if (separatorIndex === -1) continue;
    const key = line.slice(0, separatorIndex).trim();
    const value = line.slice(separatorIndex + 1).trim();
    if (key) {
      manifest[key] = value;
    }
  }

  const files: WorkspaceBundleFile[] = [];
  for (const match of bundleText.matchAll(FILE_MARKER_RE)) {
    files.push({
      path: match[1],
      language: match[2],
      priority: match[3] === 'normal'
        ? []
        : match[3].split(',').map((item) => item.trim()).filter(Boolean),
      size_bytes: Number.parseInt(match[4] ?? '0', 10) || 0,
      text: match[5] ?? '',
    });
  }

  return {
    archive_name: manifest.archive_name ?? 'workspace bundle',
    included_files: parseManifestInt(manifest.included_files) || files.length,
    omitted_files: parseManifestInt(manifest.omitted_files),
    languages: manifest.languages ?? '',
    entry_points: splitManifestValue(manifest.entry_points),
    suspicious_files: splitManifestValue(manifest.suspicious_files),
    manifest_files: splitManifestValue(manifest.manifest_files),
    root_dirs: splitManifestValue(manifest.root_dirs),
    prioritized_paths: files.map((file) => file.path),
    bundle_note: manifest.bundle_note ?? '',
    files,
  };
}
