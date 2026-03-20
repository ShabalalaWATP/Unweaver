import { useState, useCallback } from 'react';
import { X, ClipboardPaste } from 'lucide-react';

interface PasteInputProps {
  onSubmit: (text: string, filename?: string, language?: string) => void | Promise<void>;
  onClose: () => void;
}

const LANGUAGES = [
  '',
  'javascript',
  'typescript',
  'python',
  'powershell',
  'vbscript',
  'csharp',
  'java',
  'php',
  'ruby',
  'go',
  'rust',
  'shell',
  'bat',
  'perl',
  'lua',
];

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
    borderRadius: 'var(--radius-xl, 14px)',
    width: 580,
    maxWidth: '90vw',
    maxHeight: '80vh',
    display: 'flex',
    flexDirection: 'column',
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
    padding: '16px 20px',
    flex: 1,
    overflow: 'auto',
  } as React.CSSProperties,
  field: {
    marginBottom: '12px',
  } as React.CSSProperties,
  label: {
    display: 'block',
    fontSize: '11px',
    fontWeight: 600,
    color: 'var(--text-secondary)',
    textTransform: 'uppercase',
    letterSpacing: '0.04em',
    marginBottom: '6px',
  } as React.CSSProperties,
  row: {
    display: 'flex',
    gap: '12px',
  } as React.CSSProperties,
  input: {
    flex: 1,
    padding: '8px 12px',
    fontSize: '13px',
    background: 'var(--bg-primary)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-sm)',
    color: 'var(--text-primary)',
    outline: 'none',
    fontFamily: 'var(--font-mono)',
  } as React.CSSProperties,
  select: {
    padding: '8px 12px',
    fontSize: '13px',
    background: 'var(--bg-primary)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-sm)',
    color: 'var(--text-primary)',
    outline: 'none',
    cursor: 'pointer',
    minWidth: 140,
  } as React.CSSProperties,
  textarea: {
    width: '100%',
    minHeight: 220,
    padding: '10px 12px',
    fontSize: '12px',
    fontFamily: 'var(--font-mono)',
    background: 'var(--bg-primary)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-sm)',
    color: 'var(--text-primary)',
    outline: 'none',
    resize: 'vertical',
    lineHeight: '1.5',
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
  submitBtn: {
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

export default function PasteInput({ onSubmit, onClose }: PasteInputProps) {
  const [text, setText] = useState('');
  const [filename, setFilename] = useState('');
  const [language, setLanguage] = useState('');

  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = useCallback(async () => {
    if (!text.trim() || submitting) return;
    setSubmitting(true);
    setError(null);
    try {
      await onSubmit(text, filename || undefined, language || undefined);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Submit failed. Please try again.');
      setSubmitting(false);
    }
  }, [text, filename, language, onSubmit, submitting]);

  return (
    <div style={s.overlay} onClick={onClose}>
      <div style={s.modal} onClick={(e) => e.stopPropagation()}>
        <div style={s.header}>
          <span style={s.title}>Paste Sample Code</span>
          <button style={s.closeBtn} onClick={onClose}>
            <X size={16} />
          </button>
        </div>
        <div style={s.body}>
          <div style={s.field}>
            <div style={s.row}>
              <div style={{ flex: 1 }}>
                <label style={s.label}>Filename (optional)</label>
                <input
                  style={s.input}
                  value={filename}
                  onChange={(e) => setFilename(e.target.value)}
                  placeholder="sample.js"
                />
              </div>
              <div>
                <label style={s.label}>Language</label>
                <select
                  style={s.select}
                  value={language}
                  onChange={(e) => setLanguage(e.target.value)}
                >
                  <option value="">Auto-detect</option>
                  {LANGUAGES.filter(Boolean).map((l) => (
                    <option key={l} value={l}>
                      {l}
                    </option>
                  ))}
                </select>
              </div>
            </div>
          </div>
          <div style={s.field}>
            <label style={s.label}>Obfuscated Code</label>
            <textarea
              style={s.textarea}
              value={text}
              onChange={(e) => setText(e.target.value)}
              placeholder="Paste obfuscated code here..."
              autoFocus
            />
          </div>
          {error && (
            <div style={{ marginTop: 8, padding: '8px 12px', background: 'var(--danger-muted)', border: '1px solid var(--danger)', borderRadius: 'var(--radius-sm)', color: 'var(--danger)', fontSize: '12px' }}>
              {error}
            </div>
          )}
        </div>
        <div style={s.footer}>
          <button style={s.cancelBtn} onClick={onClose}>
            Cancel
          </button>
          <button
            style={{ ...s.submitBtn, opacity: text.trim() && !submitting ? 1 : 0.4 }}
            onClick={handleSubmit}
            disabled={!text.trim() || submitting}
          >
            <ClipboardPaste size={12} />
            {submitting ? 'Submitting...' : 'Submit'}
          </button>
        </div>
      </div>
    </div>
  );
}
