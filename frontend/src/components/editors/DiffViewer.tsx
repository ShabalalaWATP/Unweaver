import ReactDiffViewer, { DiffMethod } from 'react-diff-viewer-continued';

interface DiffViewerProps {
  original: string;
  recovered: string;
}

const darkStyles = {
  variables: {
    dark: {
      diffViewerBackground: '#0d1117',
      diffViewerColor: '#e6edf3',
      addedBackground: '#1a3a24',
      addedColor: '#3fb950',
      removedBackground: '#4a1c1c',
      removedColor: '#f85149',
      wordAddedBackground: '#1a4a28',
      wordRemovedBackground: '#5a2020',
      addedGutterBackground: '#1a3a24',
      removedGutterBackground: '#4a1c1c',
      gutterBackground: '#161b22',
      gutterBackgroundDark: '#0d1117',
      highlightBackground: '#21262d',
      highlightGutterBackground: '#21262d',
      codeFoldGutterBackground: '#161b22',
      codeFoldBackground: '#161b22',
      emptyLineBackground: '#0d1117',
      gutterColor: '#8b949e',
      addedGutterColor: '#3fb950',
      removedGutterColor: '#f85149',
      codeFoldContentColor: '#8b949e',
      diffViewerTitleBackground: '#161b22',
      diffViewerTitleColor: '#e6edf3',
      diffViewerTitleBorderColor: '#30363d',
    },
  },
  line: {
    padding: '2px 8px',
    fontSize: '12px',
    fontFamily: "'Cascadia Code', 'JetBrains Mono', 'Fira Code', 'Consolas', monospace",
  },
  gutter: {
    padding: '2px 8px',
    fontSize: '11px',
    minWidth: '40px',
  },
  contentText: {
    fontFamily: "'Cascadia Code', 'JetBrains Mono', 'Fira Code', 'Consolas', monospace",
    fontSize: '12px',
  },
};

export default function DiffViewer({ original, recovered }: DiffViewerProps) {
  return (
    <div style={{ height: '100%', overflow: 'auto' }}>
      <ReactDiffViewer
        oldValue={original}
        newValue={recovered}
        splitView={true}
        useDarkTheme={true}
        compareMethod={DiffMethod.LINES}
        styles={darkStyles}
        leftTitle="Original (Obfuscated)"
        rightTitle="Recovered (Deobfuscated)"
        showDiffOnly={false}
      />
    </div>
  );
}
