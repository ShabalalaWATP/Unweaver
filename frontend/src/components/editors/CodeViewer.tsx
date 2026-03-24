import { useRef, useEffect } from 'react';
import Editor, { type OnMount } from '@monaco-editor/react';
import { useTheme } from '@/contexts/ThemeContext';

interface CodeViewerProps {
  value: string;
  language?: string | null;
  readOnly?: boolean;
  wordWrap?: boolean;
  height?: string;
  onChange?: (value: string | undefined) => void;
  /** When set, scroll to and highlight the first occurrence of this text. */
  highlightText?: string | null;
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
  highlightText,
}: CodeViewerProps) {
  const { isDark } = useTheme();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const editorRef = useRef<any>(null);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const decorationsRef = useRef<any>(null);

  const handleMount: OnMount = (editor) => {
    editorRef.current = editor;
  };

  // When highlightText changes, find and scroll to it.
  useEffect(() => {
    const editor = editorRef.current;
    if (!editor || !highlightText) return;

    const model = editor.getModel();
    if (!model) return;

    const matches = model.findMatches(
      highlightText,
      true,   // searchOnlyEditableRange = false (search all)
      false,  // isRegex
      false,  // matchCase
      null,   // wordSeparators
      false,  // captureMatches
      1,      // limitResultCount
    );

    if (matches.length > 0) {
      const range = matches[0].range;
      editor.revealLineInCenter(range.startLineNumber);
      editor.setSelection(range);

      // Add highlight decoration
      decorationsRef.current = editor.deltaDecorations(
        decorationsRef.current ?? [],
        [{
          range,
          options: {
            isWholeLine: true,
            className: 'unweaver-finding-highlight',
            overviewRuler: { color: 'var(--accent)', position: 1 },
          },
        }],
      );

      // Clear highlight after 4 seconds
      setTimeout(() => {
        if (editorRef.current && decorationsRef.current) {
          editorRef.current.deltaDecorations(decorationsRef.current, []);
          decorationsRef.current = null;
        }
      }, 4000);
    }
  }, [highlightText]);

  return (
    <Editor
      height={height}
      defaultLanguage={resolveLanguage(language)}
      language={resolveLanguage(language)}
      value={value}
      theme={isDark ? 'vs-dark' : 'light'}
      onChange={onChange}
      onMount={handleMount}
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
