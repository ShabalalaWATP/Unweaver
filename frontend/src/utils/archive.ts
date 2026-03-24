import { zip, type AsyncZippable } from 'fflate';

type DirectoryFile = File & { webkitRelativePath?: string };
type WorkspaceArchiveFile = File & {
  unweaverUploadKind?: 'folder-archive';
  unweaverSourceName?: string;
  unweaverSourceFileCount?: number;
};
type DirectoryPickerFileHandle = {
  kind: 'file';
  name: string;
  getFile: () => Promise<File>;
};
type DirectoryPickerDirectoryHandle = {
  kind: 'directory';
  name: string;
  values: () => AsyncIterable<DirectoryPickerHandle>;
};
type DirectoryPickerHandle = DirectoryPickerFileHandle | DirectoryPickerDirectoryHandle;

function normaliseRelativePath(path: string): string | null {
  const cleaned = path.replace(/\\/g, '/').trim();
  if (!cleaned) return null;

  const parts = cleaned.split('/').filter((part) => part && part !== '.');
  if (parts.length === 0 || parts.some((part) => part === '..')) {
    return null;
  }
  return parts.join('/');
}

function sanitiseArchiveName(name: string): string {
  const trimmed = name.trim().replace(/[^a-zA-Z0-9._-]+/g, '_');
  const cleaned = trimmed.replace(/^_+|_+$/g, '');
  return cleaned || 'codebase';
}

function insertArchiveEntry(
  tree: AsyncZippable,
  relativePath: string,
  data: Uint8Array,
): void {
  const parts = relativePath.split('/');
  let cursor = tree;

  for (const segment of parts.slice(0, -1)) {
    const existing = cursor[segment];
    if (!existing || existing instanceof Uint8Array || Array.isArray(existing)) {
      const branch: AsyncZippable = {};
      cursor[segment] = branch;
      cursor = branch;
      continue;
    }
    cursor = existing as AsyncZippable;
  }

  cursor[parts[parts.length - 1]] = data;
}

function getRootDirectoryName(files: DirectoryFile[]): string {
  const first = files.find((file) => file.webkitRelativePath)?.webkitRelativePath;
  if (!first) return 'codebase';
  const normalised = normaliseRelativePath(first);
  if (!normalised) return 'codebase';
  return sanitiseArchiveName(normalised.split('/')[0] || 'codebase');
}

async function collectDirectoryHandleFiles(
  handle: DirectoryPickerDirectoryHandle,
  rootName: string,
  prefix = '',
): Promise<DirectoryFile[]> {
  const files: DirectoryFile[] = [];

  for await (const entry of handle.values()) {
    const relativePath = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.kind === 'directory') {
      files.push(...await collectDirectoryHandleFiles(entry, rootName, relativePath));
      continue;
    }

    const file = await entry.getFile();
    const fileWithRelativePath = Object.defineProperty(file, 'webkitRelativePath', {
      value: `${rootName}/${relativePath}`,
      configurable: true,
    }) as DirectoryFile;
    files.push(fileWithRelativePath);
  }

  return files;
}

export async function createArchiveFromDirectory(
  selectedFiles: FileList | File[],
): Promise<File> {
  const files = Array.from(selectedFiles as ArrayLike<File>) as DirectoryFile[];
  if (files.length === 0) {
    throw new Error('Selected folder is empty.');
  }

  const archiveTree: AsyncZippable = {};
  let addedFiles = 0;

  for (const file of files) {
    const relativePath = normaliseRelativePath(file.webkitRelativePath || file.name);
    if (!relativePath) continue;
    insertArchiveEntry(archiveTree, relativePath, new Uint8Array(await file.arrayBuffer()));
    addedFiles += 1;
  }

  if (addedFiles === 0) {
    throw new Error('Selected folder did not contain any files that could be archived.');
  }

  const archiveBytes = await new Promise<Uint8Array>((resolve, reject) => {
    zip(archiveTree, { level: 6 }, (err, data) => {
      if (err) {
        reject(err);
        return;
      }
      resolve(data);
    });
  });

  const archiveBuffer = archiveBytes.buffer.slice(
    archiveBytes.byteOffset,
    archiveBytes.byteOffset + archiveBytes.byteLength,
  ) as ArrayBuffer;

  const archiveFile = new File(
    [archiveBuffer],
    `${getRootDirectoryName(files)}.zip`,
    { type: 'application/zip' },
  ) as WorkspaceArchiveFile;

  Object.defineProperties(archiveFile, {
    unweaverUploadKind: { value: 'folder-archive', configurable: true },
    unweaverSourceName: { value: getRootDirectoryName(files), configurable: true },
    unweaverSourceFileCount: { value: files.length, configurable: true },
  });

  return archiveFile;
}

export async function createArchiveFromDirectoryHandle(
  handle: DirectoryPickerDirectoryHandle,
): Promise<File> {
  const rootName = sanitiseArchiveName(handle.name || 'codebase');
  const files = await collectDirectoryHandleFiles(handle, rootName);

  if (files.length === 0) {
    throw new Error('Selected folder is empty.');
  }

  return createArchiveFromDirectory(files);
}
