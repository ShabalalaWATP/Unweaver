import Editor from '@monaco-editor/react';

interface CodeViewerProps {
  value: string;
  language?: string | null;
  readOnly?: boolean;
  wordWrap?: boolean;
  height?: string;
  onChange?: (value: string | undefined) => void;
}

const LANG_MAP: Record<string, string> = {
  javascript: 'javascript',
  js: 'javascript',
  typescript: 'typescript',
  ts: 'typescript',
  python: 'python',
  py: 'python',
  powershell: 'powershell',
  ps1: 'powershell',
  vbscript: 'vb',
  vbs: 'vb',
  vb: 'vb',
  csharp: 'csharp',
  'c#': 'csharp',
  java: 'java',
  php: 'php',
  ruby: 'ruby',
  go: 'go',
  rust: 'rust',
  shell: 'shell',
  bash: 'shell',
  bat: 'bat',
  cmd: 'bat',
  xml: 'xml',
  html: 'html',
  json: 'json',
  yaml: 'yaml',
  sql: 'sql',
  perl: 'perl',
  lua: 'lua',
  r: 'r',
};

function resolveLanguage(lang?: string | null): string {
  if (!lang) return 'plaintext';
  const lower = lang.toLowerCase().trim();
  return LANG_MAP[lower] ?? 'plaintext';
}

export default function CodeViewer({
  value,
  language,
  readOnly = true,
  wordWrap = true,
  height = '100%',
  onChange,
}: CodeViewerProps) {
  return (
    <Editor
      height={height}
      defaultLanguage={resolveLanguage(language)}
      language={resolveLanguage(language)}
      value={value}
      theme="vs-dark"
      onChange={onChange}
      options={{
        readOnly,
        wordWrap: wordWrap ? 'on' : 'off',
        minimap: { enabled: false },
        lineNumbers: 'on',
        scrollBeyondLastLine: false,
        fontSize: 12,
        fontFamily: "'Cascadia Code', 'JetBrains Mono', 'Fira Code', 'Consolas', monospace",
        renderLineHighlight: 'gutter',
        padding: { top: 8, bottom: 8 },
        scrollbar: {
          verticalScrollbarSize: 8,
          horizontalScrollbarSize: 8,
        },
        overviewRulerLanes: 0,
        hideCursorInOverviewRuler: true,
        overviewRulerBorder: false,
        contextmenu: true,
        automaticLayout: true,
      }}
    />
  );
}
