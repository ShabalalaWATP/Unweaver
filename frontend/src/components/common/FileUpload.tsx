import { useState, useCallback, useRef } from 'react';
import { Upload, X, FileText, AlertCircle } from 'lucide-react';

interface FileUploadProps {
  onUpload: (file: File) => void | Promise<void>;
  onClose: () => void;
  maxSizeMB?: number;
}

const MAX_SIZE_DEFAULT = 5; // 5 MB

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
  fileInfo: {
    marginTop: '12px',
    padding: '10px 12px',
    background: 'var(--bg-primary)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-sm)',
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
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

export default function FileUpload({
  onUpload,
  onClose,
  maxSizeMB = MAX_SIZE_DEFAULT,
}: FileUploadProps) {
  const [file, setFile] = useState<File | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const validateFile = useCallback(
    (f: File): boolean => {
      const maxBytes = maxSizeMB * 1024 * 1024;
      if (f.size > maxBytes) {
        setError(`File too large. Maximum size is ${maxSizeMB} MB.`);
        return false;
      }
      setError(null);
      return true;
    },
    [maxSizeMB],
  );

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragging(false);
      const f = e.dataTransfer.files[0];
      if (f && validateFile(f)) {
        setFile(f);
      }
    },
    [validateFile],
  );

  const handleFileSelect = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const f = e.target.files?.[0];
      if (f && validateFile(f)) {
        setFile(f);
      }
    },
    [validateFile],
  );

  const [uploading, setUploading] = useState(false);

  const handleUpload = useCallback(async () => {
    if (!file || uploading) return;
    setUploading(true);
    setError(null);
    try {
      await onUpload(file);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Upload failed. Please try again.');
      setUploading(false);
    }
  }, [file, onUpload, uploading]);

  return (
    <div style={s.overlay} onClick={onClose}>
      <div style={s.modal} onClick={(e) => e.stopPropagation()}>
        <div style={s.header}>
          <span style={s.title}>Upload Sample</span>
          <button style={s.closeBtn} onClick={onClose}>
            <X size={16} />
          </button>
        </div>
        <div style={s.body}>
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
              {dragging ? 'Drop file here' : 'Drag & drop a file or click to browse'}
            </div>
            <div style={s.hint}>Max {maxSizeMB} MB</div>
          </div>
          <input
            ref={inputRef}
            type="file"
            style={{ display: 'none' }}
            onChange={handleFileSelect}
          />
          {file && (
            <div style={s.fileInfo}>
              <FileText size={14} style={{ color: 'var(--accent)', flexShrink: 0 }} />
              <span style={s.fileName}>{file.name}</span>
              <span style={s.fileSize}>{formatSize(file.size)}</span>
              <button
                style={{ ...s.closeBtn, padding: '2px' }}
                onClick={() => { setFile(null); setError(null); }}
              >
                <X size={12} />
              </button>
            </div>
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
            style={{ ...s.uploadBtn, opacity: file && !uploading ? 1 : 0.4 }}
            onClick={handleUpload}
            disabled={!file || uploading}
          >
            <Upload size={12} />
            {uploading ? 'Uploading...' : 'Upload'}
          </button>
        </div>
      </div>
    </div>
  );
}
