import { parse } from "@babel/parser";
import { webcrack } from "webcrack";

const NUMERIC_TEXT_RE = /^(?:0x[0-9a-f]+|\d+)$/i;
const OBFUSCATED_NAME_RE = /^(?:_0x[0-9a-f]+|_[A-Za-z0-9]{1,4}|[A-Za-z]{1,2}\d+)$/;

function readStdin() {
  return new Promise((resolve, reject) => {
    let data = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (chunk) => {
      data += chunk;
    });
    process.stdin.on("end", () => resolve(data));
    process.stdin.on("error", reject);
  });
}

function emit(payload) {
  process.stdout.write(JSON.stringify(payload));
}

function buildParserPlugins(language = "") {
  const plugins = new Set([
    "estree",
    "jsx",
    "typescript",
    "decorators-legacy",
    "classProperties",
    "classPrivateProperties",
    "classPrivateMethods",
    "dynamicImport",
    "importMeta",
    "topLevelAwait",
    "optionalChaining",
    "nullishCoalescingOperator",
    "objectRestSpread",
    "optionalCatchBinding",
    "exportDefaultFrom",
    "exportNamespaceFrom",
    "numericSeparator",
    "logicalAssignment",
  ]);
  const lowered = String(language || "").toLowerCase().trim();
  if (lowered === "jsx") {
    plugins.delete("typescript");
  }
  if (lowered === "ts" || lowered === "typescript" || lowered === "tsx") {
    plugins.add("typescript");
    plugins.add("jsx");
  }
  return [...plugins];
}

function parseProgram(code, language = "") {
  const attempts = [
    { sourceType: "unambiguous" },
    { sourceType: "module" },
    { sourceType: "script" },
  ];
  const plugins = buildParserPlugins(language);
  const errors = [];

  for (const attempt of attempts) {
    try {
      const program = parse(code, {
        sourceType: attempt.sourceType,
        attachComment: false,
        errorRecovery: false,
        plugins,
      });
      return {
        ok: true,
        program,
        sourceType: attempt.sourceType,
      };
    } catch (error) {
      errors.push({
        sourceType: attempt.sourceType,
        message: String(error?.message || error),
      });
    }
  }

  return { ok: false, errors };
}

function isNode(value) {
  return Boolean(value && typeof value === "object" && typeof value.type === "string");
}

function walk(node, visitor, parent = null, field = "") {
  if (!isNode(node)) {
    return;
  }
  visitor(node, parent, field);
  for (const [childField, child] of Object.entries(node)) {
    if (childField === "loc") {
      continue;
    }
    if (Array.isArray(child)) {
      for (const item of child) {
        if (isNode(item)) {
          walk(item, visitor, node, childField);
        }
      }
      continue;
    }
    if (isNode(child)) {
      walk(child, visitor, node, childField);
    }
  }
}

function walkWithoutNestedFunctions(node, visitor, parent = null, field = "", root = node) {
  if (!isNode(node)) {
    return;
  }
  visitor(node, parent, field);
  for (const [childField, child] of Object.entries(node)) {
    if (childField === "loc") {
      continue;
    }
    if (Array.isArray(child)) {
      for (const item of child) {
        if (!isNode(item)) {
          continue;
        }
        if (item !== root && /Function(?:Declaration|Expression)$/.test(item.type)) {
          continue;
        }
        if (item !== root && item.type === "ArrowFunctionExpression") {
          continue;
        }
        walkWithoutNestedFunctions(item, visitor, node, childField, root);
      }
      continue;
    }
    if (!isNode(child)) {
      continue;
    }
    if (child !== root && /Function(?:Declaration|Expression)$/.test(child.type)) {
      continue;
    }
    if (child !== root && child.type === "ArrowFunctionExpression") {
      continue;
    }
    walkWithoutNestedFunctions(child, visitor, node, childField, root);
  }
}

function applyEdits(code, edits) {
  let output = code;
  let cursor = output.length + 1;
  const sorted = [...edits].sort((left, right) => {
    if (left.start !== right.start) {
      return right.start - left.start;
    }
    return right.end - left.end;
  });
  for (const edit of sorted) {
    if (edit.start < 0 || edit.end < edit.start || edit.end > cursor) {
      continue;
    }
    output = output.slice(0, edit.start) + edit.replacement + output.slice(edit.end);
    cursor = edit.start;
  }
  return output;
}

function normalizeWhitespace(code) {
  return code.replace(/\n{3,}/g, "\n\n").trim();
}

function jsonString(value) {
  return JSON.stringify(String(value));
}

function isIdentifier(node, name = "") {
  return node?.type === "Identifier" && (!name || node.name === name);
}

function getLiteralString(node) {
  if (!node) {
    return null;
  }
  if (node.type === "Literal" && typeof node.value === "string") {
    return node.value;
  }
  return null;
}

function parseNumericText(value) {
  const text = String(value || "").trim();
  if (!NUMERIC_TEXT_RE.test(text)) {
    return null;
  }
  return text.toLowerCase().startsWith("0x") ? Number.parseInt(text, 16) : Number.parseInt(text, 10);
}

function evaluateNumeric(node, env = {}) {
  if (!node) {
    return null;
  }
  if (node.type === "Literal") {
    if (typeof node.value === "number" && Number.isFinite(node.value)) {
      return node.value;
    }
    if (typeof node.value === "string") {
      return parseNumericText(node.value);
    }
    return null;
  }
  if (node.type === "Identifier") {
    const value = env[node.name];
    return typeof value === "number" && Number.isFinite(value) ? value : null;
  }
  if (node.type === "UnaryExpression") {
    const value = evaluateNumeric(node.argument, env);
    if (value == null) {
      return null;
    }
    if (node.operator === "+") {
      return +value;
    }
    if (node.operator === "-") {
      return -value;
    }
    if (node.operator === "~") {
      return ~value;
    }
    return null;
  }
  if (node.type === "UpdateExpression" && node.argument?.type === "Identifier") {
    const value = evaluateNumeric(node.argument, env);
    if (value == null) {
      return null;
    }
    if (node.operator === "++") {
      return value + 1;
    }
    if (node.operator === "--") {
      return value - 1;
    }
  }
  if (node.type === "BinaryExpression") {
    const left = evaluateNumeric(node.left, env);
    const right = evaluateNumeric(node.right, env);
    if (left == null || right == null) {
      return null;
    }
    switch (node.operator) {
      case "+":
        return left + right;
      case "-":
        return left - right;
      case "*":
        return left * right;
      case "/":
        return right === 0 ? null : left / right;
      case "%":
        return right === 0 ? null : left % right;
      case "<<":
        return left << right;
      case ">>":
        return left >> right;
      case ">>>":
        return left >>> right;
      case "&":
        return left & right;
      case "|":
        return left | right;
      case "^":
        return left ^ right;
      default:
        return null;
    }
  }
  if (node.type === "AssignmentExpression" && node.operator === "=" && node.right) {
    return evaluateNumeric(node.right, env);
  }
  return null;
}

function isStringArrayExpression(node) {
  return node?.type === "ArrayExpression" && Array.isArray(node.elements) && node.elements.every((element) => {
    if (element == null) {
      return false;
    }
    return element.type === "Literal" && typeof element.value === "string";
  });
}

function stringArrayValues(node) {
  if (!isStringArrayExpression(node)) {
    return null;
  }
  return node.elements.map((element) => String(element.value));
}

function rotateArray(values, count, direction) {
  if (!Array.isArray(values) || values.length === 0) {
    return values;
  }
  let signed = count;
  if (direction === "right") {
    signed = -count;
  }
  const offset = ((signed % values.length) + values.length) % values.length;
  return [...values.slice(offset), ...values.slice(0, offset)];
}

function renderArrayDeclaration(kind, name, values) {
  return `${kind} ${name} = [${values.map((value) => jsonString(value)).join(", ")}];`;
}

function unwrapIifeFunction(expression) {
  if (!expression) {
    return null;
  }
  if (expression.type === "CallExpression" && (expression.callee?.type === "FunctionExpression" || expression.callee?.type === "ArrowFunctionExpression")) {
    return { call: expression, fn: expression.callee };
  }
  if (expression.type === "UnaryExpression" && expression.argument?.type === "CallExpression") {
    const call = expression.argument;
    if (call.callee?.type === "FunctionExpression" || call.callee?.type === "ArrowFunctionExpression") {
      return { call, fn: call.callee };
    }
  }
  return null;
}

function detectRotationDirection(functionNode, arrayParamName) {
  let direction = null;
  walkWithoutNestedFunctions(functionNode.body, (node) => {
    if (direction || node.type !== "CallExpression") {
      return;
    }
    const callee = node.callee;
    if (callee?.type !== "MemberExpression" || !callee.computed) {
      return;
    }
    if (!isIdentifier(callee.object, arrayParamName)) {
      return;
    }
    const outerProperty = getLiteralString(callee.property);
    if (outerProperty == null || node.arguments.length !== 1) {
      return;
    }
    const nested = node.arguments[0];
    if (nested?.type !== "CallExpression") {
      return;
    }
    const nestedCallee = nested.callee;
    if (nestedCallee?.type !== "MemberExpression" || !nestedCallee.computed) {
      return;
    }
    if (!isIdentifier(nestedCallee.object, arrayParamName)) {
      return;
    }
    const innerProperty = getLiteralString(nestedCallee.property);
    if (outerProperty === "push" && innerProperty === "shift") {
      direction = "left";
    } else if (outerProperty === "unshift" && innerProperty === "pop") {
      direction = "right";
    }
  });
  if (direction) {
    return direction;
  }

  walkWithoutNestedFunctions(functionNode.body, (node) => {
    if (direction || node.type !== "CallExpression") {
      return;
    }
    const callee = node.callee;
    if (callee?.type !== "MemberExpression" || callee.computed) {
      return;
    }
    if (!isIdentifier(callee.object, arrayParamName)) {
      return;
    }
    const outerProperty = callee.property?.name;
    if (!outerProperty || node.arguments.length !== 1) {
      return;
    }
    const nested = node.arguments[0];
    if (nested?.type !== "CallExpression") {
      return;
    }
    const nestedCallee = nested.callee;
    if (nestedCallee?.type !== "MemberExpression" || nestedCallee.computed) {
      return;
    }
    if (!isIdentifier(nestedCallee.object, arrayParamName)) {
      return;
    }
    const innerProperty = nestedCallee.property?.name;
    if (outerProperty === "push" && innerProperty === "shift") {
      direction = "left";
    } else if (outerProperty === "unshift" && innerProperty === "pop") {
      direction = "right";
    }
  });
  return direction;
}

function detectRotationDirectionAnyDepth(functionNode, arrayParamName) {
  let direction = null;
  walk(functionNode.body, (node) => {
    if (direction || node.type !== "CallExpression") {
      return;
    }
    const callee = node.callee;
    if (callee?.type === "MemberExpression" && isIdentifier(callee.object, arrayParamName)) {
      const outerProperty = callee.computed ? getLiteralString(callee.property) : callee.property?.name;
      if (!outerProperty || node.arguments.length !== 1) {
        return;
      }
      const nested = node.arguments[0];
      if (nested?.type !== "CallExpression") {
        return;
      }
      const nestedCallee = nested.callee;
      if (nestedCallee?.type !== "MemberExpression" || !isIdentifier(nestedCallee.object, arrayParamName)) {
        return;
      }
      const innerProperty = nestedCallee.computed ? getLiteralString(nestedCallee.property) : nestedCallee.property?.name;
      if (outerProperty === "push" && innerProperty === "shift") {
        direction = "left";
      } else if (outerProperty === "unshift" && innerProperty === "pop") {
        direction = "right";
      }
    }
  });
  return direction;
}

function extractLookupIndex(node, paramName) {
  if (!node) {
    return null;
  }
  if (isIdentifier(node, paramName)) {
    return { kind: "param", offset: 0 };
  }
  if (node.type === "Literal") {
    const numeric = evaluateNumeric(node, {});
    if (numeric != null) {
      return { kind: "literal", value: numeric };
    }
    return null;
  }
  if (node.type === "BinaryExpression") {
    if (node.operator === "-" && isIdentifier(node.left, paramName)) {
      const value = evaluateNumeric(node.right, {});
      if (value != null) {
        return { kind: "param", offset: value };
      }
    }
    if (node.operator === "+" && isIdentifier(node.left, paramName)) {
      const value = evaluateNumeric(node.right, {});
      if (value != null) {
        return { kind: "param", offset: -value };
      }
    }
  }
  return null;
}

function extractMemberLookup(node, paramName) {
  if (!node || node.type !== "MemberExpression" || !node.computed) {
    return null;
  }
  if (node.optional || node.object?.type !== "Identifier") {
    return null;
  }
  const lookup = extractLookupIndex(node.property, paramName);
  if (!lookup) {
    return null;
  }
  if (lookup.kind === "param") {
    return {
      arrayName: node.object.name,
      offset: lookup.offset || 0,
    };
  }
  if (lookup.kind === "literal") {
    return {
      arrayName: node.object.name,
      literalIndex: lookup.value,
    };
  }
  return null;
}

function extractWrapper(functionNode, functionName, arrays) {
  const params = Array.isArray(functionNode.params) ? functionNode.params : [];
  if (!params.length || params[0]?.type !== "Identifier") {
    return null;
  }

  const paramName = params[0].name;
  const bodyStatements = functionNode.body?.type === "BlockStatement"
    ? functionNode.body.body || []
    : [{ type: "ReturnStatement", argument: functionNode.body }];
  let paramOffset = 0;
  const aliases = new Map();

  for (const statement of bodyStatements) {
    if (statement?.type === "ExpressionStatement" && statement.expression?.type === "AssignmentExpression") {
      const expression = statement.expression;
      if (expression.operator === "=" && isIdentifier(expression.left, paramName) && expression.right?.type === "BinaryExpression" && expression.right.operator === "-" && isIdentifier(expression.right.left, paramName)) {
        const value = evaluateNumeric(expression.right.right, {});
        if (value != null) {
          paramOffset += value;
        }
      } else if (expression.operator === "-=" && isIdentifier(expression.left, paramName)) {
        const value = evaluateNumeric(expression.right, {});
        if (value != null) {
          paramOffset += value;
        }
      }
    }

    if (statement?.type === "VariableDeclaration") {
      for (const declaration of statement.declarations || []) {
        if (!isIdentifier(declaration.id)) {
          continue;
        }
        const lookup = extractMemberLookup(declaration.init, paramName);
        if (!lookup || !arrays.has(lookup.arrayName) || typeof lookup.literalIndex === "number") {
          continue;
        }
        aliases.set(declaration.id.name, {
          arrayName: lookup.arrayName,
          offset: paramOffset + (lookup.offset || 0),
        });
      }
    }

    if (statement?.type === "ReturnStatement") {
      const directLookup = extractMemberLookup(statement.argument, paramName);
      if (directLookup && arrays.has(directLookup.arrayName) && typeof directLookup.literalIndex !== "number") {
        return {
          functionName,
          arrayName: directLookup.arrayName,
          offset: paramOffset + (directLookup.offset || 0),
        };
      }

      if (isIdentifier(statement.argument)) {
        const alias = aliases.get(statement.argument.name);
        if (alias) {
          return {
            functionName,
            arrayName: alias.arrayName,
            offset: alias.offset,
          };
        }
      }
    }
  }

  return null;
}

function countIdentifierUses(code, name) {
  const pattern = new RegExp(`\\b${name.replace(/[.*+?^${}()|[\\]\\\\]/g, "\\$&")}\\b`, "g");
  let count = 0;
  while (pattern.exec(code)) {
    count += 1;
  }
  return count;
}

function countCallSites(code, name) {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const pattern = new RegExp(`\\b${escaped}\\s*\\(`, "g");
  let count = 0;
  while (pattern.exec(code)) {
    count += 1;
  }
  return count;
}

function resolveArrays(code, language = "") {
  const parsed = parseProgram(code, language);
  if (!parsed.ok) {
    return {
      ok: false,
      error: "parse_error",
      errors: parsed.errors,
    };
  }

  const { program } = parsed;
  const arrays = new Map();
  const arrayDeclarations = new Map();
  const wrapperCandidates = new Map();
  const wrappers = new Map();
  const helperSourcesByArray = new Map();
  const rotationEdits = [];
  const rotationMatches = [];
  const staticRewrites = [];
  const replacements = [];

  walk(program, (node, parent) => {
    if (node.type === "VariableDeclarator" && isIdentifier(node.id) && isStringArrayExpression(node.init)) {
      const parentKind = parent?.type === "VariableDeclaration" ? String(parent.kind || "var") : "var";
      const values = stringArrayValues(node.init);
      if (!values) {
        return;
      }
      arrays.set(node.id.name, values);
      if (parent?.type === "VariableDeclaration" && (parent.declarations || []).length === 1) {
        arrayDeclarations.set(node.id.name, {
          kind: parentKind,
          start: parent.start,
          end: parent.end,
          source: code.slice(parent.start, parent.end),
          original: [...values],
        });
      }
      return;
    }

    if (node.type === "FunctionDeclaration" && isIdentifier(node.id)) {
      wrapperCandidates.set(node.id.name, {
        node,
        start: node.start,
        end: node.end,
        source: code.slice(node.start, node.end),
      });
      return;
    }

    if (node.type === "VariableDeclarator" && isIdentifier(node.id) && (node.init?.type === "FunctionExpression" || node.init?.type === "ArrowFunctionExpression")) {
      if (parent?.type === "VariableDeclaration" && (parent.declarations || []).length === 1) {
        wrapperCandidates.set(node.id.name, {
          node: node.init,
          start: parent.start,
          end: parent.end,
          source: code.slice(parent.start, parent.end),
        });
      }
      return;
    }

    if (node.type === "ExpressionStatement") {
      const iife = unwrapIifeFunction(node.expression);
      if (!iife) {
        return;
      }
      const [firstArg, secondArg] = iife.call.arguments || [];
      if (!isIdentifier(firstArg) || !arrays.has(firstArg.name)) {
        return;
      }
      const fnParams = iife.fn.params || [];
      if (!fnParams.length || fnParams[0]?.type !== "Identifier") {
        return;
      }
      const helperDirection = detectRotationDirectionAnyDepth(iife.fn, fnParams[0].name);
      if (helperDirection) {
        const sources = helperSourcesByArray.get(firstArg.name) || [];
        sources.push(code.slice(node.start, node.end));
        helperSourcesByArray.set(firstArg.name, sources);
      }
      const direction = detectRotationDirection(iife.fn, fnParams[0].name);
      if (!direction) {
        return;
      }
      const count = evaluateNumeric(secondArg, {});
      if (count == null) {
        return;
      }
      arrays.set(firstArg.name, rotateArray(arrays.get(firstArg.name), count, direction));
      rotationEdits.push({ start: node.start, end: node.end, replacement: "" });
      rotationMatches.push({
        array: firstArg.name,
        count,
        direction,
      });
      staticRewrites.push({
        type: "rotation_runtime_removed",
        array: firstArg.name,
        direction,
        count,
      });
    }
  });

  for (const [name, meta] of arrayDeclarations.entries()) {
    const rotated = arrays.get(name);
    if (!rotated || meta.original.join("\u0000") === rotated.join("\u0000")) {
      continue;
    }
    rotationEdits.push({
      start: meta.start,
      end: meta.end,
      replacement: renderArrayDeclaration(meta.kind, name, rotated),
    });
    staticRewrites.push({
      type: "array_rotation_fold",
      array: name,
      rotation: rotationMatches
        .filter((item) => item.array === name)
        .reduce((total, item) => total + (item.direction === "left" ? item.count : -item.count), 0),
    });
  }

  for (const [name, candidate] of wrapperCandidates.entries()) {
    const wrapper = extractWrapper(candidate.node, name, arrays);
    if (!wrapper) {
      continue;
    }
    wrappers.set(name, {
      ...wrapper,
      start: candidate.start,
      end: candidate.end,
      source: candidate.source,
      uses: 0,
    });
  }

  const replacementEdits = [];
  walk(program, (node, parent, field) => {
    if (node.type === "CallExpression" && isIdentifier(node.callee) && wrappers.has(node.callee.name)) {
      const wrapper = wrappers.get(node.callee.name);
      if (!wrapper || !node.arguments?.length) {
        return;
      }
      const argValue = evaluateNumeric(node.arguments[0], {});
      if (argValue == null) {
        return;
      }
      const values = arrays.get(wrapper.arrayName);
      if (!values) {
        return;
      }
      const resolvedIndex = argValue - wrapper.offset;
      if (resolvedIndex < 0 || resolvedIndex >= values.length) {
        return;
      }
      wrapper.uses += 1;
      const resolved = values[resolvedIndex];
      replacementEdits.push({
        start: node.start,
        end: node.end,
        replacement: jsonString(resolved),
      });
      replacements.push({
        type: "wrapper_call",
        original: code.slice(node.start, node.end),
        resolved,
        function: wrapper.functionName,
        index: resolvedIndex,
      });
      return;
    }

    if (node.type === "MemberExpression" && node.computed && !node.optional && isIdentifier(node.object)) {
      const values = arrays.get(node.object.name);
      if (!values) {
        return;
      }
      const index = evaluateNumeric(node.property, {});
      if (index == null || index < 0 || index >= values.length) {
        return;
      }
      if (parent?.type === "AssignmentExpression" && field === "left") {
        return;
      }
      const resolved = values[index];
      replacementEdits.push({
        start: node.start,
        end: node.end,
        replacement: jsonString(resolved),
      });
      replacements.push({
        type: "array_access",
        original: code.slice(node.start, node.end),
        resolved,
        array: node.object.name,
        index,
      });
    }
  });

  let output = applyEdits(code, [...rotationEdits, ...replacementEdits]);

  for (const [name, wrapper] of wrappers.entries()) {
    if (wrapper.uses <= 0) {
      continue;
    }
    const callUses = countCallSites(output, name);
    const declarationCallAllowance = wrapper.source.startsWith(`function ${name}(`) ? 1 : 0;
    if (callUses <= declarationCallAllowance && wrapper.source && output.includes(wrapper.source)) {
      output = output.replace(wrapper.source, "");
      staticRewrites.push({
        type: "wrapper_runtime_removed",
        function: name,
      });
    }
  }

  for (const [name, declaration] of arrayDeclarations.entries()) {
    const helperSources = helperSourcesByArray.get(name) || [];
    for (const helperSource of helperSources) {
      if (!helperSource || !output.includes(helperSource)) {
        continue;
      }
      const candidate = output.replace(helperSource, "");
      if (countIdentifierUses(candidate, name) <= 1) {
        output = candidate;
        staticRewrites.push({
          type: "unused_rotation_helper_removed",
          array: name,
        });
      }
    }

    if (countIdentifierUses(output, name) > 1) {
      continue;
    }
    const rotatedSource = renderArrayDeclaration(declaration.kind, name, arrays.get(name) || declaration.original);
    if (output.includes(rotatedSource)) {
      output = output.replace(rotatedSource, "");
      staticRewrites.push({
        type: "unused_array_removed",
        array: name,
      });
    } else if (declaration.source && output.includes(declaration.source)) {
      output = output.replace(declaration.source, "");
      staticRewrites.push({
        type: "unused_array_removed",
        array: name,
      });
    }
    if (
      rotationMatches.some((item) => item.array === name)
      && !staticRewrites.some((item) => item.type === "unused_rotation_helper_removed" && item.array === name)
    ) {
      staticRewrites.push({
        type: "unused_rotation_helper_removed",
        array: name,
      });
    }
  }

  output = normalizeWhitespace(output);
  const techniques = ["array_lookup_resolution", "javascript_ast_array_resolution"];
  if (rotationMatches.length) {
    techniques.push("deterministic_array_rotation_fold");
  }

  return {
    ok: true,
    changed: output !== normalizeWhitespace(code),
    output,
    arraysFound: arrays.size,
    wrappersFound: wrappers.size,
    rotationApplied: rotationMatches.length > 0,
    replacements,
    staticRewrites,
    detectedTechniques: techniques,
    parser: "babel_estree",
    sourceType: parsed.sourceType,
  };
}

function looksLikeBundle(code) {
  const excerpt = String(code || "").slice(0, 25000);
  return (
    /__webpack_require__/.test(excerpt) ||
    /webpackJsonp/.test(excerpt) ||
    /parcelRequire/.test(excerpt) ||
    /\bmodules\s*:\s*{/.test(excerpt) ||
    /\brequire\s*=\s*function\s*\(/.test(excerpt) ||
    /\(function\s*\(\s*modules\s*\)/.test(excerpt) ||
    /\bmodule\.exports\b/.test(excerpt)
  );
}

async function runWebcrack(code) {
  const result = await webcrack(code, {
    jsx: true,
    unpack: true,
    deobfuscate: true,
    unminify: true,
    mangle: false,
  });

  return {
    ok: true,
    changed: result.code !== code,
    output: result.code,
    bundle: result.bundle
      ? {
          type: result.bundle.type,
          entryId: result.bundle.entryId,
          moduleCount: typeof result.bundle.modules?.size === "number" ? result.bundle.modules.size : null,
        }
      : null,
    heuristics: {
      bundleLike: looksLikeBundle(code),
    },
  };
}

async function main() {
  try {
    const raw = await readStdin();
    const request = raw ? JSON.parse(raw) : {};
    const action = String(request.action || "").trim();
    const code = String(request.code || "");
    const language = String(request.language || "");

    if (action === "validate") {
      const parsed = parseProgram(code, language);
      emit({
        ok: parsed.ok,
        parser: "babel_estree",
        sourceType: parsed.sourceType || null,
        errors: parsed.errors || [],
      });
      return;
    }

    if (action === "parse") {
      const parsed = parseProgram(code, language);
      emit({
        ok: parsed.ok,
        parser: "babel_estree",
        sourceType: parsed.sourceType || null,
        ast: parsed.ok ? parsed.program : null,
        errors: parsed.errors || [],
      });
      return;
    }

    if (action === "resolve_arrays") {
      emit(resolveArrays(code, language));
      return;
    }

    if (action === "webcrack") {
      emit(await runWebcrack(code));
      return;
    }

    emit({
      ok: false,
      error: `unknown_action:${action || "missing"}`,
    });
  } catch (error) {
    emit({
      ok: false,
      error: String(error?.message || error),
    });
  }
}

main();
