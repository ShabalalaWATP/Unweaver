'use strict';

const vm = require('node:vm');

function readStdin() {
  return new Promise((resolve, reject) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => {
      data += chunk;
    });
    process.stdin.on('end', () => resolve(data));
    process.stdin.on('error', reject);
  });
}

function isUsefulText(value) {
  if (typeof value !== 'string') {
    return false;
  }
  const trimmed = value.trim();
  if (!trimmed || trimmed.length < 3) {
    return false;
  }
  if (/^(?:return|throw)\b/.test(trimmed)) {
    return true;
  }
  if (/[;{}()[\]]/.test(trimmed)) {
    return true;
  }
  if (/\b(?:function|var|let|const|alert|console|document|window|eval)\b/.test(trimmed)) {
    return true;
  }
  return /[A-Za-z]/.test(trimmed) && trimmed.length >= 8;
}

function createSandbox(captures) {
  const intercept = (kind, value) => {
    const text = String(value ?? '');
    captures.push({ kind, body: text });
    return text;
  };

  const interceptFunction = (...args) => {
    const body = String(args.length ? args[args.length - 1] : '');
    captures.push({ kind: 'function', body });
    return function interceptedFunctionResult() {
      return body;
    };
  };

  const sandbox = {
    __interceptEval: (value) => intercept('eval', value),
    __interceptFunction: interceptFunction,
    __interceptTimer: (value) => intercept('timer', value),
    __captures: captures,
    console: { log() {}, info() {}, warn() {}, error() {} },
  };
  sandbox.globalThis = sandbox;
  sandbox.window = sandbox;
  sandbox.self = sandbox;
  sandbox.global = sandbox;
  return sandbox;
}

function patchRuntime(context) {
  vm.runInContext(
    `
      const __OriginalFunction = Function;
      globalThis.eval = __interceptEval;
      globalThis.Function = __interceptFunction;
      globalThis.setTimeout = __interceptTimer;
      globalThis.setInterval = __interceptTimer;
      globalThis.alert = __interceptEval;
      Object.defineProperty(__OriginalFunction.prototype, 'constructor', {
        value: __interceptFunction,
        configurable: true,
        writable: true
      });
    `,
    context,
    { timeout: 100 }
  );
}

function chooseDecodedPayload(result, captures) {
  const candidates = [];
  for (const capture of captures) {
    if (isUsefulText(capture.body)) {
      candidates.push(capture.body);
    }
  }
  if (typeof result === 'string' && isUsefulText(result)) {
    candidates.push(result);
  }
  candidates.sort((left, right) => right.length - left.length);
  return candidates.length ? candidates[0] : '';
}

async function main() {
  try {
    const raw = await readStdin();
    const payload = JSON.parse(raw || '{}');
    const source = String(payload.code || '');
    const captures = [];
    const sandbox = createSandbox(captures);
    vm.createContext(sandbox);
    patchRuntime(sandbox);

    let result = null;
    let error = '';
    try {
      result = vm.runInContext(source, sandbox, {
        timeout: Number(payload.timeout_ms || 750),
      });
    } catch (exc) {
      error = String(exc && exc.message ? exc.message : exc);
    }

    const decoded = chooseDecodedPayload(result, captures);
    process.stdout.write(JSON.stringify({
      ok: Boolean(decoded),
      decoded,
      result: typeof result === 'string' ? result : '',
      captures,
      error,
    }));
  } catch (exc) {
    process.stdout.write(JSON.stringify({
      ok: false,
      decoded: '',
      captures: [],
      error: String(exc && exc.message ? exc.message : exc),
    }));
  }
}

main();
