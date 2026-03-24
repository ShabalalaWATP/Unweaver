import { useState, useCallback, useEffect, useRef } from 'react';
import { Upload, X, FileText, AlertCircle, FolderOpen } from 'lucide-react';

import { createArchiveFromDirectory, createArchiveFromDirectoryHandle } from '@/utils/archive';
import signalChamberGraphic from '@/assets/graphics/signal-chamber.svg';

interface FileUploadProps {
  onUpload: (files: File[]) => void | Promise<void>;
  onClose: () => void;
  maxSizeMB?: number;
  maxArchiveSizeMB?: number;
}

const MAX_SIZE_DEFAULT = 5; // 5 MB for single files
const MAX_ARCHIVE_SIZE_DEFAULT = 25; // 25 MB for compressed archives
const ACCEPTED_FILE_TYPES = [
  '.zip', '.tar', '.tgz', '.gz',
  '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs',
  '.py', '.ps1', '.psm1', '.psd1',
  '.vbs', '.vb', '.cs', '.java', '.php', '.rb', '.go', '.rs',
  '.sh', '.bat', '.cmd', '.json', '.yaml', '.yml', '.xml', '.txt',
].join(',');

type DirectoryInputElement = HTMLInputElement & {
  webkitdirectory?: boolean;
  directory?: boolean;
};
type WorkspaceArchiveFile = File & {
  unweaverUploadKind?: 'folder-archive';
  unweaverSourceName?: string;
  unweaverSourceFileCount?: number;
};
type DirectoryPickerEntry =
  | {
    kind: 'file';
    name: string;
    getFile: () => Promise<File>;
  }
  | {
    kind: 'directory';
    name: string;
    values: () => AsyncIterable<DirectoryPickerEntry>;
  };
type DirectoryPickerHandle = {
  kind: 'directory';
  name: string;
  values: () => AsyncIterable<DirectoryPickerEntry>;
};
type DirectoryPickerWindow = Window & {
  showDirectoryPicker?: () => Promise<DirectoryPickerHandle>;
};

const s = {
  overlay: {
    position: 'fixed',
    inset: 0,
    background: 'var(--overlay-bg)',
    backdropFilter: 'blur(4px)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    zIndex: 1000,
    animation: 'unweaver-fade-in 0.15s ease',
  } as React.CSSProperties,
  modal: {
    background: 'var(--bg-secondary)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-xl)',
    width: 460,
    maxWidth: '90vw',
    overflow: 'hidden',
    boxShadow: 'var(--shadow-lg, 0 4px 20px rgba(0,0,0,0.4))',
    animation: 'unweaver-fade-in 0.2s ease',
  } as React.CSSProperties,
  header: {
    padding: '12px 16px',
    borderBottom: '1px solid var(--border)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
  } as React.CSSProperties,
  title: {
    fontSize: '14px',
    fontWeight: 600,
    color: 'var(--text-primary)',
  } as React.CSSProperties,
  closeBtn: {
    padding: '4px',
    borderRadius: 'var(--radius-sm)',
    color: 'var(--text-muted)',
    cursor: 'pointer',
    display: 'flex',
    alignItems: 'center',
  } as React.CSSProperties,
  body: {
    padding: '20px',
  } as React.CSSProperties,
  visualIntro: {
    marginBottom: '16px',
    padding: '14px',
    borderRadius: 'var(--radius-lg)',
    background: 'linear-gradient(160deg, rgba(88,166,255,0.12) 0%, rgba(94,234,212,0.05) 52%, rgba(255,255,255,0.02) 100%)',
    border: '1px solid rgba(88,166,255,0.14)',
    display: 'flex',
    gap: '14px',
    alignItems: 'center',
    overflow: 'hidden',
  } as React.CSSProperties,
  visualGraphic: {
    width: 112,
    flexShrink: 0,
    borderRadius: '16px',
    overflow: 'hidden',
    border: '1px solid rgba(255,255,255,0.08)',
    background: 'rgba(0,0,0,0.12)',
  } as React.CSSProperties,
  visualGraphicImg: {
    width: '100%',
    display: 'block',
  } as React.CSSProperties,
  visualCopy: {
    display: 'flex',
    flexDirection: 'column',
    gap: '6px',
    minWidth: 0,
  } as React.CSSProperties,
  visualLabel: {
    fontSize: '10px',
    textTransform: 'uppercase',
    letterSpacing: '0.12em',
    color: 'var(--accent-bright)',
    fontWeight: 700,
  } as React.CSSProperties,
  visualTitle: {
    fontSize: '15px',
    fontWeight: 700,
    color: 'var(--text-primary)',
    lineHeight: 1.15,
  } as React.CSSProperties,
  visualBody: {
    fontSize: '12px',
    color: 'var(--text-secondary)',
    lineHeight: 1.5,
  } as React.CSSProperties,
  dropzone: {
    border: '2px dashed var(--border)',
    borderRadius: 'var(--radius-md)',
    padding: '32px 20px',
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    gap: '10px',
    cursor: 'pointer',
    transition: 'border-color 0.15s, background 0.15s',
    textAlign: 'center',
  } as React.CSSProperties,
  dropzoneActive: {
    borderColor: 'var(--accent)',
    background: 'var(--accent-muted)',
  } as React.CSSProperties,
  icon: {
    color: 'var(--text-muted)',
  } as React.CSSProperties,
  instruction: {
    fontSize: '13px',
    color: 'var(--text-secondary)',
  } as React.CSSProperties,
  hint: {
    fontSize: '11px',
    color: 'var(--text-muted)',
  } as React.CSSProperties,
  pickerRow: {
    marginTop: '12px',
    display: 'flex',
    gap: '8px',
  } as React.CSSProperties,
  pickerBtn: {
    flex: 1,
    padding: '8px 12px',
    fontSize: '12px',
    fontWeight: 600,
    borderRadius: 'var(--radius-sm)',
    border: '1px solid var(--border)',
    background: 'var(--bg-tertiary)',
    color: 'var(--text-secondary)',
    cursor: 'pointer',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '6px',
  } as React.CSSProperties,
  fileInfo: {
    padding: '10px 12px',
    background: 'var(--bg-primary)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-sm)',
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
  } as React.CSSProperties,
  selectionMeta: {
    marginTop: '12px',
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    gap: '12px',
    fontSize: '11px',
    color: 'var(--text-muted)',
  } as React.CSSProperties,
  fileList: {
    marginTop: '8px',
    display: 'flex',
    flexDirection: 'column',
    gap: '8px',
    maxHeight: '180px',
    overflowY: 'auto',
  } as React.CSSProperties,
  fileName: {
    fontSize: '12px',
    fontFamily: 'var(--font-mono)',
    color: 'var(--text-primary)',
    flex: 1,
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
  } as React.CSSProperties,
  fileSize: {
    fontSize: '10px',
    color: 'var(--text-muted)',
    fontFamily: 'var(--font-mono)',
  } as React.CSSProperties,
  error: {
    marginTop: '8px',
    padding: '8px 12px',
    background: 'var(--danger-muted)',
    border: '1px solid var(--danger)',
    borderRadius: 'var(--radius-sm)',
    color: 'var(--danger)',
    fontSize: '12px',
    display: 'flex',
    alignItems: 'center',
    gap: '6px',
  } as React.CSSProperties,
  footer: {
    padding: '12px 16px',
    borderTop: '1px solid var(--border)',
    display: 'flex',
    justifyContent: 'flex-end',
    gap: '8px',
  } as React.CSSProperties,
  cancelBtn: {
    padding: '6px 14px',
    fontSize: '12px',
    fontWeight: 500,
    borderRadius: 'var(--radius-sm)',
    border: '1px solid var(--border)',
    background: 'var(--bg-tertiary)',
    color: 'var(--text-secondary)',
    cursor: 'pointer',
  } as React.CSSProperties,
  uploadBtn: {
    padding: '6px 14px',
    fontSize: '12px',
    fontWeight: 600,
    borderRadius: 'var(--radius-sm)',
    border: 'none',
    background: 'var(--accent)',
    color: '#fff',
    cursor: 'pointer',
    display: 'flex',
    alignItems: 'center',
    gap: '5px',
  } as React.CSSProperties,
};

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function isArchiveFile(file: File): boolean {
  const name = file.name.toLowerCase();
  return (
    name.endsWith('.zip')
    || name.endsWith('.tar')
    || name.endsWith('.tgz')
    || name.endsWith('.tar.gz')
    || name.endsWith('.gz')
  );
}

function isWorkspaceArchiveFile(file: File): file is WorkspaceArchiveFile {
  return (file as WorkspaceArchiveFile).unweaverUploadKind === 'folder-archive';
}

export default function FileUpload({
  onUpload,
  onClose,
  maxSizeMB = MAX_SIZE_DEFAULT,
  maxArchiveSizeMB = MAX_ARCHIVE_SIZE_DEFAULT,
}: FileUploadProps) {
  const [files, setFiles] = useState<File[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const directoryInputRef = useRef<HTMLInputElement>(null);
  const [preparingFolder, setPreparingFolder] = useState(false);
  const [uploading, setUploading] = useState(false);

  useEffect(() => {
    const directoryInput = directoryInputRef.current as DirectoryInputElement | null;
    if (!directoryInput) return;
    directoryInput.webkitdirectory = true;
    directoryInput.directory = true;
    directoryInput.setAttribute('webkitdirectory', '');
    directoryInput.setAttribute('directory', '');
    directoryInput.multiple = true;
  }, []);

  const validateFiles = useCallback(
    (incomingFiles: File[]): File[] | null => {
      if (incomingFiles.length === 0) {
        setError('No files selected.');
        return null;
      }

      for (const candidate of incomingFiles) {
        const archive = isArchiveFile(candidate);
        const allowedMb = archive ? maxArchiveSizeMB : maxSizeMB;
        const maxBytes = allowedMb * 1024 * 1024;
        if (candidate.size > maxBytes) {
          setError(
            `"${candidate.name}" is too large. Maximum ${archive ? 'archive' : 'file'} size is ${allowedMb} MB.`,
          );
          return null;
        }
      }

      setError(null);
      return incomingFiles;
    },
    [maxArchiveSizeMB, maxSizeMB],
  );

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragging(false);
      const droppedFiles = Array.from(e.dataTransfer.files);
      const validFiles = validateFiles(droppedFiles);
      if (validFiles) {
        setFiles(validFiles);
      }
    },
    [validateFiles],
  );

  const handleFileSelect = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const selectedFiles = Array.from(e.target.files ?? []);
      const validFiles = validateFiles(selectedFiles);
      if (validFiles) {
        setFiles(validFiles);
      }
      e.target.value = '';
    },
    [validateFiles],
  );

  const handleDirectorySelect = useCallback(
    async (e: React.ChangeEvent<HTMLInputElement>) => {
      const selectedFiles = e.target.files;
      e.target.value = '';
      if (!selectedFiles || selectedFiles.length === 0) return;

      setPreparingFolder(true);
      setError(null);
      try {
        const archiveFile = await createArchiveFromDirectory(selectedFiles);
        const validFiles = validateFiles([archiveFile]);
        if (validFiles) {
          setFiles(validFiles);
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to package folder for upload.');
      } finally {
        setPreparingFolder(false);
      }
    },
    [validateFiles],
  );

  const handleChooseFolder = useCallback(async () => {
    if (preparingFolder || uploading) return;

    const showDirectoryPicker = (window as DirectoryPickerWindow).showDirectoryPicker;
    if (!showDirectoryPicker) {
      directoryInputRef.current?.click();
      return;
    }

    setPreparingFolder(true);
    setError(null);
    try {
      const selectedDirectory = await showDirectoryPicker();
      const archiveFile = await createArchiveFromDirectoryHandle(selectedDirectory);
      const validFiles = validateFiles([archiveFile]);
      if (validFiles) {
        setFiles(validFiles);
      }
    } catch (err) {
      if (err instanceof DOMException && err.name === 'AbortError') {
        return;
      }

      if (directoryInputRef.current && (err instanceof DOMException || err instanceof TypeError)) {
        directoryInputRef.current.click();
        return;
      }

      setError(err instanceof Error ? err.message : 'Failed to package folder for upload.');
    } finally {
      setPreparingFolder(false);
    }
  }, [preparingFolder, uploading, validateFiles]);

  const handleUpload = useCallback(async () => {
    if (files.length === 0 || uploading || preparingFolder) return;
    setUploading(true);
    setError(null);
    try {
      await onUpload(files);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Upload failed. Please try again.');
    } finally {
      setUploading(false);
    }
  }, [files, onUpload, preparingFolder, uploading]);

  const totalSize = files.reduce((sum, currentFile) => sum + currentFile.size, 0);
  const uploadLabel = preparingFolder
    ? 'Packing Folder...'
    : uploading
      ? 'Uploading...'
      : files.length > 1
        ? `Upload ${files.length} Files`
        : 'Upload';

  return (
    <div style={s.overlay} onClick={onClose}>
      <div style={s.modal} onClick={(e) => e.stopPropagation()}>
        <div style={s.header}>
          <span style={s.title}>Upload Sample or Codebase</span>
          <button style={s.closeBtn} onClick={onClose}>
            <X size={16} />
          </button>
        </div>
        <div style={s.body}>
          <div style={s.visualIntro}>
            <div className="unweaver-static-glow" style={s.visualGraphic}>
              <img
                src={signalChamberGraphic}
                alt="Signal chamber upload illustration"
                style={s.visualGraphicImg}
              />
            </div>
            <div style={s.visualCopy}>
              <span style={s.visualLabel}>Intake Surface</span>
              <div style={s.visualTitle}>Upload obfuscated code or a full codebase.</div>
              <div style={s.visualBody}>
                Folder uploads are archived locally in the browser before deobfuscation starts on the backend.
              </div>
            </div>
          </div>
          <div
            style={{
              ...s.dropzone,
              ...(dragging ? s.dropzoneActive : {}),
            }}
            onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
            onDragLeave={() => setDragging(false)}
            onDrop={handleDrop}
            onClick={() => inputRef.current?.click()}
          >
            <Upload size={28} style={s.icon} />
            <div style={s.instruction}>
              {dragging ? 'Drop files or archives here' : 'Drag & drop files or archives'}
            </div>
            <div style={s.hint}>
              Select one or more files, or package a whole folder locally before upload
            </div>
          </div>
          <div style={s.pickerRow}>
            <button
              style={{ ...s.pickerBtn, opacity: preparingFolder || uploading ? 0.6 : 1 }}
              type="button"
              onClick={() => inputRef.current?.click()}
              disabled={preparingFolder || uploading}
            >
              <Upload size={14} />
              Choose File
            </button>
            <button
              style={{ ...s.pickerBtn, opacity: preparingFolder || uploading ? 0.6 : 1 }}
              type="button"
              onClick={handleChooseFolder}
              disabled={preparingFolder || uploading}
            >
              <FolderOpen size={14} />
              Choose Folder
            </button>
          </div>
          <div style={{ ...s.hint, marginTop: '8px' }}>
            Choosing a folder packages it into a local `.zip` before upload.
          </div>
          <input
            ref={inputRef}
            type="file"
            multiple
            accept={ACCEPTED_FILE_TYPES}
            style={{ display: 'none' }}
            onChange={handleFileSelect}
          />
          <input
            ref={directoryInputRef}
            type="file"
            style={{ display: 'none' }}
            onChange={handleDirectorySelect}
          />
          {files.length > 0 && (
            <>
              <div style={s.selectionMeta}>
                <span>
                  {files.length} item{files.length === 1 ? '' : 's'} selected
                </span>
                <span>{formatSize(totalSize)}</span>
              </div>
              <div style={s.fileList}>
                {files.map((file) => {
                  const workspaceArchive = isWorkspaceArchiveFile(file);
                  return (
                  <div key={`${file.name}-${file.size}-${file.lastModified}`} style={s.fileInfo}>
                    <FileText size={14} style={{ color: 'var(--accent)', flexShrink: 0 }} />
                    <span style={s.fileName}>
                      {workspaceArchive
                        ? `${file.unweaverSourceName} folder (${file.unweaverSourceFileCount ?? 0} files) -> ${file.name}`
                        : file.name}
                    </span>
                    <span style={s.fileSize}>{formatSize(file.size)}</span>
                    <button
                      style={{ ...s.closeBtn, padding: '2px' }}
                      onClick={() => {
                        setFiles((currentFiles) => currentFiles.filter((candidate) => candidate !== file));
                        setError(null);
                      }}
                    >
                      <X size={12} />
                    </button>
                  </div>
                  );
                })}
              </div>
              {files.some((file) => isWorkspaceArchiveFile(file)) && (
                <div style={{ ...s.hint, marginTop: '8px' }}>
                  Folder uploads are converted into one local archive for transport, then unpacked by Unweaver into a multi-file workspace bundle after upload.
                </div>
              )}
            </>
          )}
          {error && (
            <div style={s.error}>
              <AlertCircle size={14} />
              {error}
            </div>
          )}
        </div>
        <div style={s.footer}>
          <button style={s.cancelBtn} onClick={onClose}>
            Cancel
          </button>
          <button
            style={{ ...s.uploadBtn, opacity: files.length > 0 && !uploading && !preparingFolder ? 1 : 0.4 }}
            onClick={handleUpload}
            disabled={files.length === 0 || uploading || preparingFolder}
          >
            <Upload size={12} />
            {uploadLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
