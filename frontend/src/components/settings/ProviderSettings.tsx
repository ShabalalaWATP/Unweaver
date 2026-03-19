import { useState, useCallback } from 'react';
import {
  ArrowLeft,
  Plus,
  Trash2,
  Save,
  Wifi,
  WifiOff,
  CheckCircle,
  XCircle,
  Shield,
  Loader,
} from 'lucide-react';
import { useProviders } from '@/hooks/useApi';
import type { ProviderSettings as ProviderSettingsType, MaxTokensPreset } from '@/types';

interface ProviderSettingsProps {
  onBack: () => void;
}

const s = {
  root: {
    height: '100%',
    display: 'flex',
    flexDirection: 'column',
    overflow: 'hidden',
  } as React.CSSProperties,
  header: {
    padding: '12px 16px',
    borderBottom: '1px solid var(--border)',
    background: 'var(--bg-secondary)',
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
  } as React.CSSProperties,
  backBtn: {
    padding: '4px',
    borderRadius: 'var(--radius-sm)',
    color: 'var(--text-secondary)',
    cursor: 'pointer',
    display: 'flex',
    alignItems: 'center',
    transition: 'color 0.15s',
  } as React.CSSProperties,
  title: {
    fontSize: '14px',
    fontWeight: 600,
    color: 'var(--text-primary)',
  } as React.CSSProperties,
  body: {
    display: 'flex',
    flex: 1,
    overflow: 'hidden',
  } as React.CSSProperties,
  list: {
    width: 280,
    minWidth: 280,
    borderRight: '1px solid var(--border)',
    background: 'var(--bg-secondary)',
    display: 'flex',
    flexDirection: 'column',
    overflow: 'hidden',
  } as React.CSSProperties,
  listHeader: {
    padding: '8px 12px',
    borderBottom: '1px solid var(--border)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
  } as React.CSSProperties,
  listTitle: {
    fontSize: '11px',
    fontWeight: 600,
    color: 'var(--text-muted)',
    textTransform: 'uppercase',
    letterSpacing: '0.06em',
  } as React.CSSProperties,
  addBtn: {
    padding: '3px 8px',
    fontSize: '10px',
    fontWeight: 500,
    borderRadius: 'var(--radius-sm)',
    background: 'var(--accent-muted)',
    color: 'var(--accent)',
    border: '1px solid var(--accent)',
    cursor: 'pointer',
    display: 'flex',
    alignItems: 'center',
    gap: '3px',
  } as React.CSSProperties,
  listItems: {
    flex: 1,
    overflow: 'auto',
  } as React.CSSProperties,
  listItem: {
    padding: '10px 12px',
    cursor: 'pointer',
    borderBottom: '1px solid var(--bg-tertiary)',
    transition: 'background 0.1s',
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
  } as React.CSSProperties,
  listItemActive: {
    background: 'var(--bg-tertiary)',
  } as React.CSSProperties,
  itemName: {
    fontSize: '12px',
    fontWeight: 500,
    color: 'var(--text-primary)',
    flex: 1,
  } as React.CSSProperties,
  itemModel: {
    fontSize: '10px',
    color: 'var(--text-muted)',
    fontFamily: 'var(--font-mono)',
  } as React.CSSProperties,
  activeDot: {
    width: 6,
    height: 6,
    borderRadius: '50%',
    background: 'var(--success)',
    flexShrink: 0,
  } as React.CSSProperties,
  form: {
    flex: 1,
    overflow: 'auto',
    padding: '20px 24px',
  } as React.CSSProperties,
  formTitle: {
    fontSize: '16px',
    fontWeight: 600,
    color: 'var(--text-primary)',
    marginBottom: '20px',
  } as React.CSSProperties,
  field: {
    marginBottom: '16px',
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
  input: {
    width: '100%',
    maxWidth: 400,
    padding: '8px 12px',
    fontSize: '13px',
    background: 'var(--bg-primary)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-sm)',
    color: 'var(--text-primary)',
    outline: 'none',
    fontFamily: 'var(--font-ui)',
  } as React.CSSProperties,
  monoInput: {
    fontFamily: 'var(--font-mono)',
    fontSize: '12px',
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
  } as React.CSSProperties,
  checkbox: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    fontSize: '12px',
    color: 'var(--text-secondary)',
    cursor: 'pointer',
  } as React.CSSProperties,
  actions: {
    display: 'flex',
    gap: '8px',
    marginTop: '24px',
    paddingTop: '16px',
    borderTop: '1px solid var(--border)',
  } as React.CSSProperties,
  btn: {
    padding: '8px 16px',
    fontSize: '12px',
    fontWeight: 600,
    borderRadius: 'var(--radius-sm)',
    display: 'flex',
    alignItems: 'center',
    gap: '6px',
    cursor: 'pointer',
    border: 'none',
    transition: 'opacity 0.15s',
  } as React.CSSProperties,
  saveBtn: {
    background: 'var(--accent)',
    color: '#fff',
  } as React.CSSProperties,
  deleteBtn: {
    background: 'var(--danger-muted)',
    color: 'var(--danger)',
    border: '1px solid var(--danger)',
  } as React.CSSProperties,
  testBtn: {
    background: 'var(--bg-tertiary)',
    color: 'var(--text-secondary)',
    border: '1px solid var(--border)',
  } as React.CSSProperties,
  testResult: {
    marginTop: '12px',
    padding: '8px 12px',
    borderRadius: 'var(--radius-sm)',
    fontSize: '12px',
    display: 'flex',
    alignItems: 'center',
    gap: '6px',
  } as React.CSSProperties,
  emptyForm: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    flex: 1,
    color: 'var(--text-muted)',
    fontSize: '13px',
  } as React.CSSProperties,
};

interface FormState {
  name: string;
  base_url: string;
  model_name: string;
  api_key: string;
  cert_bundle_path: string;
  use_system_trust: boolean;
  max_tokens_preset: MaxTokensPreset;
}

const EMPTY_FORM: FormState = {
  name: '',
  base_url: '',
  model_name: '',
  api_key: '',
  cert_bundle_path: '',
  use_system_trust: true,
  max_tokens_preset: '128k',
};

export default function ProviderSettingsScreen({ onBack }: ProviderSettingsProps) {
  const { providers, create, update, remove, test } = useProviders();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [isNew, setIsNew] = useState(false);
  const [form, setForm] = useState<FormState>(EMPTY_FORM);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null);
  const [saving, setSaving] = useState(false);

  const handleSelectProvider = useCallback(
    (p: ProviderSettingsType) => {
      setSelectedId(p.id);
      setIsNew(false);
      setTestResult(null);
      setForm({
        name: p.name,
        base_url: p.base_url,
        model_name: p.model_name,
        api_key: '', // Don't pre-fill masked key
        cert_bundle_path: p.cert_bundle_path ?? '',
        use_system_trust: p.use_system_trust,
        max_tokens_preset: p.max_tokens_preset,
      });
    },
    [],
  );

  const handleNew = useCallback(() => {
    setSelectedId(null);
    setIsNew(true);
    setTestResult(null);
    setForm(EMPTY_FORM);
  }, []);

  const handleSave = useCallback(async () => {
    setSaving(true);
    try {
      const payload = {
        name: form.name,
        base_url: form.base_url,
        model_name: form.model_name,
        api_key: form.api_key,
        cert_bundle_path: form.cert_bundle_path || undefined,
        use_system_trust: form.use_system_trust,
        max_tokens_preset: form.max_tokens_preset,
      };
      if (isNew) {
        const p = await create(payload);
        setSelectedId(p.id);
        setIsNew(false);
      } else if (selectedId) {
        await update(selectedId, payload);
      }
    } catch (err) {
      console.error('Save failed:', err);
    } finally {
      setSaving(false);
    }
  }, [form, isNew, selectedId, create, update]);

  const handleDelete = useCallback(async () => {
    if (!selectedId) return;
    await remove(selectedId);
    setSelectedId(null);
    setIsNew(false);
    setForm(EMPTY_FORM);
  }, [selectedId, remove]);

  const handleTest = useCallback(async () => {
    if (!selectedId) return;
    setTesting(true);
    setTestResult(null);
    try {
      const result = await test(selectedId);
      setTestResult(result);
    } catch (err) {
      setTestResult({ success: false, message: err instanceof Error ? err.message : String(err) });
    } finally {
      setTesting(false);
    }
  }, [selectedId, test]);

  const updateField = useCallback(
    <K extends keyof FormState>(key: K, value: FormState[K]) => {
      setForm((prev) => ({ ...prev, [key]: value }));
    },
    [],
  );

  const showForm = isNew || selectedId;

  return (
    <div style={s.root}>
      <div style={s.header}>
        <button
          style={s.backBtn}
          onClick={onBack}
          onMouseEnter={(e) => { e.currentTarget.style.color = 'var(--text-primary)'; }}
          onMouseLeave={(e) => { e.currentTarget.style.color = 'var(--text-secondary)'; }}
        >
          <ArrowLeft size={16} />
        </button>
        <span style={s.title}>Provider Settings</span>
      </div>
      <div style={s.body}>
        {/* Provider list */}
        <div style={s.list}>
          <div style={s.listHeader}>
            <span style={s.listTitle}>Providers</span>
            <button style={s.addBtn} onClick={handleNew}>
              <Plus size={10} />
              New
            </button>
          </div>
          <div style={s.listItems}>
            {providers.map((p) => (
              <div
                key={p.id}
                style={{
                  ...s.listItem,
                  ...(selectedId === p.id ? s.listItemActive : {}),
                }}
                onClick={() => handleSelectProvider(p)}
                onMouseEnter={(e) => {
                  if (selectedId !== p.id) e.currentTarget.style.background = 'var(--bg-tertiary)';
                }}
                onMouseLeave={(e) => {
                  if (selectedId !== p.id) e.currentTarget.style.background = 'transparent';
                }}
              >
                {p.is_active && <div style={s.activeDot} />}
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={s.itemName}>{p.name}</div>
                  <div style={s.itemModel}>{p.model_name}</div>
                </div>
                {p.is_active ? (
                  <Wifi size={12} style={{ color: 'var(--success)', flexShrink: 0 }} />
                ) : (
                  <WifiOff size={12} style={{ color: 'var(--text-muted)', flexShrink: 0 }} />
                )}
              </div>
            ))}
            {providers.length === 0 && (
              <div style={{ padding: '12px', color: 'var(--text-muted)', fontSize: '12px' }}>
                No providers configured
              </div>
            )}
          </div>
        </div>

        {/* Form */}
        {showForm ? (
          <div style={s.form}>
            <div style={s.formTitle}>
              {isNew ? 'New Provider' : 'Edit Provider'}
            </div>

            <div style={s.field}>
              <label style={s.label}>Provider Name</label>
              <input
                style={s.input}
                value={form.name}
                onChange={(e) => updateField('name', e.target.value)}
                placeholder="e.g. Local vLLM"
              />
            </div>

            <div style={s.field}>
              <label style={s.label}>Base URL</label>
              <input
                style={{ ...s.input, ...s.monoInput }}
                value={form.base_url}
                onChange={(e) => updateField('base_url', e.target.value)}
                placeholder="https://localhost:8443/v1"
              />
            </div>

            <div style={s.field}>
              <label style={s.label}>Model Name</label>
              <input
                style={{ ...s.input, ...s.monoInput }}
                value={form.model_name}
                onChange={(e) => updateField('model_name', e.target.value)}
                placeholder="e.g. deepseek-coder-v2"
              />
            </div>

            <div style={s.field}>
              <label style={s.label}>API Key</label>
              <input
                style={{ ...s.input, ...s.monoInput }}
                type="password"
                value={form.api_key}
                onChange={(e) => updateField('api_key', e.target.value)}
                placeholder={isNew ? 'Enter API key' : 'Leave empty to keep existing'}
              />
            </div>

            <div style={s.field}>
              <label style={s.label}>Max Tokens Preset</label>
              <select
                style={s.select}
                value={form.max_tokens_preset}
                onChange={(e) => updateField('max_tokens_preset', e.target.value as MaxTokensPreset)}
              >
                <option value="128k">128K</option>
                <option value="200k">200K</option>
              </select>
            </div>

            <div style={s.field}>
              <label style={s.label}>Certificate Bundle Path</label>
              <input
                style={{ ...s.input, ...s.monoInput }}
                value={form.cert_bundle_path}
                onChange={(e) => updateField('cert_bundle_path', e.target.value)}
                placeholder="/path/to/ca-bundle.crt (optional)"
              />
            </div>

            <div style={s.field}>
              <label style={s.checkbox}>
                <input
                  type="checkbox"
                  checked={form.use_system_trust}
                  onChange={(e) => updateField('use_system_trust', e.target.checked)}
                  style={{ accentColor: 'var(--accent)' }}
                />
                <Shield size={12} />
                Use system trust store
              </label>
            </div>

            {/* Test result */}
            {testResult && (
              <div
                style={{
                  ...s.testResult,
                  background: testResult.success ? 'var(--success-muted)' : 'var(--danger-muted)',
                  color: testResult.success ? 'var(--success)' : 'var(--danger)',
                  border: `1px solid ${testResult.success ? 'var(--success)' : 'var(--danger)'}`,
                }}
              >
                {testResult.success ? <CheckCircle size={14} /> : <XCircle size={14} />}
                {testResult.message}
              </div>
            )}

            <div style={s.actions}>
              <button
                style={{ ...s.btn, ...s.saveBtn, opacity: saving ? 0.6 : 1 }}
                onClick={handleSave}
                disabled={saving}
              >
                <Save size={12} />
                {isNew ? 'Create' : 'Update'}
              </button>
              {!isNew && selectedId && (
                <button
                  style={{ ...s.btn, ...s.testBtn }}
                  onClick={handleTest}
                  disabled={testing}
                >
                  {testing ? <Loader size={12} /> : <Wifi size={12} />}
                  Test Connection
                </button>
              )}
              {!isNew && selectedId && (
                <button
                  style={{ ...s.btn, ...s.deleteBtn }}
                  onClick={handleDelete}
                >
                  <Trash2 size={12} />
                  Delete
                </button>
              )}
            </div>
          </div>
        ) : (
          <div style={s.emptyForm}>
            Select a provider or create a new one
          </div>
        )}
      </div>
    </div>
  );
}
