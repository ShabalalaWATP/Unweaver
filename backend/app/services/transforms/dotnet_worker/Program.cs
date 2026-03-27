using System.Reflection;
using System.Reflection.Emit;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Resources;
using System.IO.Compression;
using System.Text;
using System.Text.Json;

var input = JsonSerializer.Deserialize<InputPayload>(Console.In.ReadToEnd()) ?? new InputPayload(null);
if (string.IsNullOrWhiteSpace(input.AssemblyBase64))
{
    Write(new WorkerResponse(false, "missing_input"));
    return;
}

byte[] assemblyBytes;
try
{
    assemblyBytes = Convert.FromBase64String(input.AssemblyBase64);
}
catch (Exception exc)
{
    Write(new WorkerResponse(false, $"base64_decode_failed: {exc.Message}"));
    return;
}

try
{
    using var stream = new MemoryStream(assemblyBytes, writable: false);
    using var peReader = new PEReader(stream, PEStreamOptions.LeaveOpen);
    if (!peReader.HasMetadata)
    {
        Write(new WorkerResponse(false, "pe_has_no_metadata"));
        return;
    }

    var reader = peReader.GetMetadataReader();
    var assemblyDefinition = reader.IsAssembly ? reader.GetAssemblyDefinition() : default;
    string assemblyName = reader.IsAssembly ? reader.GetString(assemblyDefinition.Name) : "<module>";
    string moduleName = reader.GetString(reader.GetModuleDefinition().Name);

    var typeNames = new List<string>();
    var methodNames = new List<string>();
    var references = new List<string>();
    var resources = new List<string>();
    var extractedStrings = new HashSet<string>(StringComparer.Ordinal);
    var suspiciousReferences = new HashSet<string>(StringComparer.Ordinal);
    var proxyMethods = new List<string>();
    var methodSummaries = new List<MethodSummary>();
    var embeddedResources = ResourceHelpers.ExtractEmbeddedResources(peReader, reader);
    var resourceTextByName = embeddedResources
        .Where(item => !string.IsNullOrWhiteSpace(item.TextPreview) || !string.IsNullOrWhiteSpace(item.DecodedTextPreview))
        .ToDictionary(
            item => item.Name,
            item => item.DecodedTextPreview ?? item.TextPreview ?? string.Empty,
            StringComparer.OrdinalIgnoreCase
        );
    var resourceEntryTextByName = embeddedResources
        .SelectMany(item => item.Entries ?? [])
        .Where(item => !string.IsNullOrWhiteSpace(item.TextPreview) || !string.IsNullOrWhiteSpace(item.DecodedTextPreview))
        .GroupBy(item => item.Name, StringComparer.OrdinalIgnoreCase)
        .ToDictionary(
            group => group.Key,
            group => group.First().DecodedTextPreview ?? group.First().TextPreview ?? string.Empty,
            StringComparer.OrdinalIgnoreCase
        );

    foreach (var handle in reader.AssemblyReferences)
    {
        var reference = reader.GetAssemblyReference(handle);
        references.Add(reader.GetString(reference.Name));
    }

    var typeNameByHandle = new Dictionary<TypeDefinitionHandle, string>();
    foreach (var handle in reader.TypeDefinitions)
    {
        var typeDefinition = reader.GetTypeDefinition(handle);
        string ns = reader.GetString(typeDefinition.Namespace);
        string name = reader.GetString(typeDefinition.Name);
        string fullName = string.IsNullOrWhiteSpace(ns) ? name : $"{ns}.{name}";
        if (name == "<Module>")
        {
            continue;
        }
        typeNameByHandle[handle] = fullName;
        typeNames.Add(fullName);
    }

    foreach (var handle in reader.ManifestResources)
    {
        var resource = reader.GetManifestResource(handle);
        resources.Add(reader.GetString(resource.Name));
    }
    foreach (var resource in embeddedResources)
    {
        if (!string.IsNullOrWhiteSpace(resource.TextPreview))
        {
            extractedStrings.Add(resource.TextPreview);
        }
        if (!string.IsNullOrWhiteSpace(resource.DecodedTextPreview))
        {
            extractedStrings.Add(resource.DecodedTextPreview);
        }
        foreach (var resourceEntry in resource.Entries ?? [])
        {
            if (!string.IsNullOrWhiteSpace(resourceEntry.TextPreview))
            {
                extractedStrings.Add(resourceEntry.TextPreview);
            }
            if (!string.IsNullOrWhiteSpace(resourceEntry.DecodedTextPreview))
            {
                extractedStrings.Add(resourceEntry.DecodedTextPreview);
            }
        }
    }

    MethodDefinitionHandle? entryPointHandle = null;
    if (reader.IsAssembly && peReader.PEHeaders.CorHeader is { EntryPointTokenOrRelativeVirtualAddress: not 0 } corHeader)
    {
        try
        {
            var entryHandle = MetadataTokens.EntityHandle(corHeader.EntryPointTokenOrRelativeVirtualAddress);
            if (entryHandle.Kind == HandleKind.MethodDefinition)
            {
                entryPointHandle = (MethodDefinitionHandle)entryHandle;
            }
        }
        catch
        {
            entryPointHandle = null;
        }
    }

    var methodWorkItems = new List<MethodWorkItem>();
    foreach (var typeHandle in reader.TypeDefinitions)
    {
        var typeDefinition = reader.GetTypeDefinition(typeHandle);
        if (!typeNameByHandle.TryGetValue(typeHandle, out var typeName))
        {
            continue;
        }

        foreach (var methodHandle in typeDefinition.GetMethods())
        {
            var methodDefinition = reader.GetMethodDefinition(methodHandle);
            string methodName = reader.GetString(methodDefinition.Name);
            string fullMethodName = $"{typeName}.{methodName}";
            methodNames.Add(fullMethodName);

            if (methodDefinition.RelativeVirtualAddress == 0)
            {
                continue;
            }

            try
            {
                var body = peReader.GetMethodBody(methodDefinition.RelativeVirtualAddress);
                var ilBytes = body.GetILBytes();
                if (ilBytes is null)
                {
                    continue;
                }
                methodWorkItems.Add(new MethodWorkItem(typeName, methodName, fullMethodName, ilBytes.ToArray()));
            }
            catch
            {
                // Ignore individual method decode failures; keep the rest.
            }
        }
    }

    var knownMethodReturns = new Dictionary<string, string>(StringComparer.Ordinal);
    var staticFieldValues = new Dictionary<string, string>(StringComparer.Ordinal);
    var latestSummaries = new Dictionary<string, IlSummary>(StringComparer.Ordinal);
    var orderedWorkItems = methodWorkItems
        .OrderBy(item => item.MethodName == ".cctor" ? 0 : 1)
        .ThenBy(item => item.FullMethodName, StringComparer.Ordinal)
        .ToList();

    for (int pass = 0; pass < 5; pass++)
    {
        bool changed = false;
        foreach (var workItem in orderedWorkItems)
        {
            var ilSummary = IlSummary.FromBytes(
                workItem.IlBytes,
                reader,
                workItem.FullMethodName,
                resourceTextByName,
                resourceEntryTextByName,
                staticFieldValues,
                knownMethodReturns
            );
            latestSummaries[workItem.FullMethodName] = ilSummary;

            if (!string.IsNullOrWhiteSpace(ilSummary.ReturnString)
                && (!knownMethodReturns.TryGetValue(workItem.FullMethodName, out var existingReturn)
                    || !string.Equals(existingReturn, ilSummary.ReturnString, StringComparison.Ordinal)))
            {
                knownMethodReturns[workItem.FullMethodName] = ilSummary.ReturnString;
                changed = true;
            }

            foreach (var fieldWrite in ilSummary.StaticFieldWrites)
            {
                if (!staticFieldValues.TryGetValue(fieldWrite.Key, out var existingValue)
                    || !string.Equals(existingValue, fieldWrite.Value, StringComparison.Ordinal))
                {
                    staticFieldValues[fieldWrite.Key] = fieldWrite.Value;
                    changed = true;
                }
            }
        }

        if (!changed)
        {
            break;
        }
    }

    foreach (var workItem in orderedWorkItems)
    {
        if (!latestSummaries.TryGetValue(workItem.FullMethodName, out var ilSummary))
        {
            continue;
        }
        foreach (var value in ilSummary.UserStrings)
        {
            extractedStrings.Add(value);
        }
        foreach (var value in ilSummary.SuspiciousReferences)
        {
            suspiciousReferences.Add(value);
        }
        methodSummaries.Add(new MethodSummary(
            workItem.FullMethodName,
            workItem.TypeName,
            workItem.MethodName,
            ilSummary.ReturnString,
            ilSummary.ProxyTarget,
            ilSummary.CallTargets.Take(20).ToList(),
            ilSummary.UserStrings.Take(20).ToList(),
            ilSummary.ResourceNames.Take(12).ToList(),
            ilSummary.SuspiciousReferences.Take(20).ToList(),
            ilSummary.InstructionCount,
            ilSummary.IsLikelyProxy
        ));
        if (ilSummary.IsLikelyProxy)
        {
            proxyMethods.Add(workItem.FullMethodName);
        }
    }

    var output = new WorkerResponse(
        true,
        null,
        AssemblyName: assemblyName,
        ModuleName: moduleName,
        MetadataVersion: reader.MetadataVersion,
        EntryPoint: entryPointHandle is MethodDefinitionHandle entry ? MetadataHelpers.ResolveMethodName(entry, reader, typeNameByHandle) : null,
        Types: typeNames.Take(80).ToList(),
        Methods: methodNames.Take(120).ToList(),
        References: references.Take(60).ToList(),
        Resources: resources.Take(40).ToList(),
        UserStrings: extractedStrings.Where(IsInterestingString).OrderByDescending(s => s.Length).Take(120).ToList(),
        SuspiciousReferences: suspiciousReferences.OrderBy(s => s).Take(80).ToList(),
        ProxyMethods: proxyMethods.Take(80).ToList(),
        MethodSummaries: methodSummaries.Take(160).ToList(),
        EmbeddedResources: embeddedResources.Take(40).ToList()
    );
    Write(output);
}
catch (Exception exc)
{
    Write(new WorkerResponse(false, $"analysis_failed: {exc.Message}"));
}

return;

static void Write(WorkerResponse response)
{
    Console.Out.Write(JsonSerializer.Serialize(response, new JsonSerializerOptions
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false,
    }));
}

static bool IsInterestingString(string value)
{
    if (string.IsNullOrWhiteSpace(value))
    {
        return false;
    }
    if (value.Length < 4)
    {
        return false;
    }
    return value.Any(ch => char.IsLetter(ch));
}

sealed class IlSummary
{
    private static readonly Dictionary<ushort, OpCode> Opcodes = BuildOpcodeMap();

    public List<string> UserStrings { get; } = new();
    public List<string> CallTargets { get; } = new();
    public List<string> ResourceNames { get; } = new();
    public Dictionary<string, string> StaticFieldWrites { get; } = new(StringComparer.Ordinal);
    public HashSet<string> SuspiciousReferences { get; } = new(StringComparer.Ordinal);
    public int InstructionCount { get; private set; }
    public bool IsLikelyProxy { get; private set; }
    public string? ReturnString { get; private set; }
    public string? ProxyTarget { get; private set; }

    public static IlSummary FromBytes(
        byte[] il,
        MetadataReader reader,
        string methodName,
        IReadOnlyDictionary<string, string> resourceTextByName,
        IReadOnlyDictionary<string, string> resourceEntryTextByName,
        IReadOnlyDictionary<string, string> staticFieldValues,
        IReadOnlyDictionary<string, string> knownMethodReturns
    )
    {
        var summary = new IlSummary();
        int offset = 0;
        int callCount = 0;
        string? lastCall = null;
        string? pendingFunctionPointer = null;
        var stack = new List<string>();
        var locals = new Dictionary<int, string>();
        var builderStates = new Dictionary<string, string>(StringComparer.Ordinal);
        int nextBuilderId = 0;

        while (offset < il.Length)
        {
            ushort rawOpcode = il[offset++];
            if (rawOpcode == 0xFE && offset < il.Length)
            {
                rawOpcode = (ushort)((rawOpcode << 8) | il[offset++]);
            }

            if (!Opcodes.TryGetValue(rawOpcode, out var opcode))
            {
                break;
            }

            summary.InstructionCount += 1;
            int operandSize = 0;
            int metadataToken = 0;
            int operandOffset = offset;
            switch (opcode.OperandType)
            {
                case OperandType.InlineNone:
                    break;
                case OperandType.ShortInlineBrTarget:
                case OperandType.ShortInlineI:
                case OperandType.ShortInlineVar:
                    operandSize = 1;
                    break;
                case OperandType.InlineVar:
                    operandSize = 2;
                    break;
                case OperandType.InlineI:
                case OperandType.InlineBrTarget:
                case OperandType.InlineField:
                case OperandType.InlineMethod:
                case OperandType.InlineSig:
                case OperandType.InlineString:
                case OperandType.InlineTok:
                case OperandType.InlineType:
                    operandSize = 4;
                    if (offset + 4 <= il.Length)
                    {
                        metadataToken = BitConverter.ToInt32(il, offset);
                    }
                    break;
                case OperandType.InlineI8:
                case OperandType.InlineR:
                    operandSize = 8;
                    break;
                case OperandType.ShortInlineR:
                    operandSize = 4;
                    break;
                case OperandType.InlineSwitch:
                    if (offset + 4 > il.Length)
                    {
                        operandSize = 0;
                        break;
                    }
                    int cases = BitConverter.ToInt32(il, offset);
                    operandSize = 4 + (cases * 4);
                    break;
            }

            if (TryGetLocalIndex(opcode, il, operandOffset, out int localIndex))
            {
                if (IsStoreLocal(opcode))
                {
                    if (stack.Count > 0)
                    {
                        string top = stack[^1];
                        stack.RemoveAt(stack.Count - 1);
                        locals[localIndex] = top;
                    }
                }
                else if (locals.TryGetValue(localIndex, out var value))
                {
                    stack.Add(value);
                }
            }
            else if (TryGetIntConstant(opcode, il, operandOffset, out int intValue))
            {
                stack.Add($"int:{intValue}");
            }
            else if (opcode == OpCodes.Dup)
            {
                if (stack.Count > 0)
                {
                    stack.Add(stack[^1]);
                }
            }
            else if (opcode == OpCodes.Pop)
            {
                if (stack.Count > 0)
                {
                    stack.RemoveAt(stack.Count - 1);
                }
            }
            else if (opcode.OperandType == OperandType.InlineString && metadataToken != 0)
            {
                try
                {
                    string value = reader.GetUserString(MetadataTokens.UserStringHandle(metadataToken));
                    if (!string.IsNullOrWhiteSpace(value))
                    {
                        summary.UserStrings.Add(value);
                        stack.Add($"str:{value}");
                    }
                }
                catch
                {
                    // Ignore malformed tokens.
                }
            }
            else if (opcode == OpCodes.Ldnull)
            {
                stack.Add("null");
            }
            else if (TryHandleStaticField(opcode, metadataToken, reader, stack, summary, staticFieldValues))
            {
            }
            else if (
                (opcode == OpCodes.Call || opcode == OpCodes.Callvirt || opcode == OpCodes.Newobj || opcode == OpCodes.Ldftn)
                && metadataToken != 0
            )
            {
                try
                {
                    string target = MetadataHelpers.ResolveEntityName(MetadataTokens.EntityHandle(metadataToken), reader);
                    summary.CallTargets.Add(target);
                    lastCall = target;
                    if (opcode == OpCodes.Ldftn)
                    {
                        pendingFunctionPointer = target;
                        stack.Add($"fn:{target}");
                    }
                    else if (TryHandleCultureFactory(target, stack))
                    {
                        callCount += 1;
                    }
                    else if (TryHandleEncodingFactory(target, stack))
                    {
                        callCount += 1;
                    }
                    else if (TryHandleBase64Decode(target, stack, summary))
                    {
                        callCount += 1;
                    }
                    else if (TryHandleStringConcat(target, stack))
                    {
                        callCount += 1;
                    }
                    else if (TryHandleManifestResourceAccess(target, stack, summary))
                    {
                        callCount += 1;
                    }
                    else if (TryHandleStreamReaderCtor(target, stack))
                    {
                        // Constructor used to wrap an embedded resource stream.
                    }
                    else if (TryHandleReadToEnd(target, stack, summary, resourceTextByName))
                    {
                        callCount += 1;
                    }
                    else if (TryHandleResourceManagerGetString(target, stack, summary, resourceEntryTextByName))
                    {
                        callCount += 1;
                    }
                    else if (TryHandleEncodingGetString(target, stack, summary))
                    {
                        callCount += 1;
                    }
                    else if (TryHandleMemoryStreamCtor(target, stack))
                    {
                    }
                    else if (TryHandleCompressionStreamCtor(target, stack, summary))
                    {
                        callCount += 1;
                    }
                    else if (opcode == OpCodes.Newobj)
                    {
                        if (pendingFunctionPointer is not null && target.EndsWith(".ctor", StringComparison.Ordinal))
                        {
                            stack.Clear();
                            stack.Add($"delegate:{pendingFunctionPointer}");
                        }
                        else if (TryHandleStringBuilderCtor(target, stack, builderStates, ref nextBuilderId))
                        {
                        }
                        else
                        {
                            stack.Clear();
                            stack.Add($"call:{target}");
                        }
                    }
                    else if (TryHandleStringBuilderAppend(target, stack, builderStates))
                    {
                        callCount += 1;
                    }
                    else if (TryHandleStringBuilderToString(target, stack, builderStates, summary))
                    {
                        callCount += 1;
                    }
                    else if (TryHandleDisposeCall(target, stack))
                    {
                    }
                    else if (opcode != OpCodes.Newobj && TryHandleKnownMethodReturn(target, stack, summary, knownMethodReturns))
                    {
                        callCount += 1;
                    }
                    else if (opcode == OpCodes.Callvirt && target.EndsWith(".Invoke", StringComparison.Ordinal) && TryPopDelegate(stack, out var delegateTarget))
                    {
                        summary.ProxyTarget = delegateTarget;
                        stack.Clear();
                        stack.Add($"call:{delegateTarget}");
                        callCount += 1;
                    }
                    else if (opcode == OpCodes.Callvirt && target.EndsWith(".Invoke", StringComparison.Ordinal) && pendingFunctionPointer is not null)
                    {
                        summary.ProxyTarget = pendingFunctionPointer;
                        stack.Clear();
                        stack.Add($"call:{pendingFunctionPointer}");
                        callCount += 1;
                    }
                    else
                    {
                        stack.Clear();
                        stack.Add($"call:{target}");
                        callCount += 1;
                    }
                    if (target.Contains("Assembly.Load", StringComparison.Ordinal)
                        || target.Contains("GetManifestResourceStream", StringComparison.Ordinal)
                        || target.Contains("Convert.FromBase64String", StringComparison.Ordinal)
                        || target.Contains("DynamicInvoke", StringComparison.Ordinal)
                        || target.Contains("System.Reflection", StringComparison.Ordinal)
                        || target.Contains("System.Runtime.InteropServices.Marshal", StringComparison.Ordinal))
                    {
                        summary.SuspiciousReferences.Add(target);
                    }
                }
                catch
                {
                    // Ignore malformed references.
                }
            }
            else if (opcode == OpCodes.Ret)
            {
                if (stack.Count > 0)
                {
                    string top = stack[^1];
                    if (top.StartsWith("str:", StringComparison.Ordinal))
                    {
                        summary.ReturnString = top[4..];
                    }
                }
            }

            offset += operandSize;
            if (offset > il.Length)
            {
                break;
            }
        }

        summary.IsLikelyProxy =
            summary.InstructionCount is >= 2 and <= 5
            && (summary.ProxyTarget is not null || (callCount == 1 && lastCall is not null))
            && !methodName.EndsWith(".ctor", StringComparison.Ordinal);
        if (
            summary.ProxyTarget is null
            && summary.IsLikelyProxy
            && lastCall is not null
            && !lastCall.StartsWith("System.", StringComparison.Ordinal)
            && !lastCall.EndsWith(".ctor", StringComparison.Ordinal)
        )
        {
            summary.ProxyTarget = lastCall;
        }

        return summary;
    }

    private static bool TryHandleEncodingFactory(string target, List<string> stack)
    {
        string? encoding = target switch
        {
            "System.Text.Encoding.get_UTF8" => "utf-8",
            "System.Text.Encoding.get_Unicode" => "utf-16le",
            "System.Text.Encoding.get_ASCII" => "ascii",
            "System.Text.Encoding.get_BigEndianUnicode" => "utf-16be",
            "System.Text.Encoding.get_Latin1" => "latin-1",
            _ => null,
        };
        if (encoding is null)
        {
            return false;
        }
        stack.Add($"encoding:{encoding}");
        return true;
    }

    private static bool TryHandleCultureFactory(string target, List<string> stack)
    {
        if (!string.Equals(target, "System.Globalization.CultureInfo.get_InvariantCulture", StringComparison.Ordinal))
        {
            return false;
        }
        stack.Add("culture:InvariantCulture");
        return true;
    }

    private static bool TryHandleResourceManagerGetString(
        string target,
        List<string> stack,
        IlSummary summary,
        IReadOnlyDictionary<string, string> resourceEntryTextByName
    )
    {
        if (!target.EndsWith("System.Resources.ResourceManager.GetString", StringComparison.Ordinal)
            && !target.EndsWith(".ResourceManager.GetString", StringComparison.Ordinal))
        {
            return false;
        }
        string? resourceKey = null;
        for (int index = stack.Count - 1; index >= 0; index--)
        {
            string value = stack[index];
            if (!value.StartsWith("str:", StringComparison.Ordinal))
            {
                continue;
            }
            resourceKey = value[4..];
            stack.RemoveRange(index, stack.Count - index);
            break;
        }
        if (string.IsNullOrWhiteSpace(resourceKey))
        {
            stack.Add($"call:{target}");
            return true;
        }
        if (!resourceEntryTextByName.TryGetValue(resourceKey, out var resolvedText))
        {
            stack.Add($"call:{target}");
            return true;
        }
        summary.ResourceNames.Add(resourceKey);
        summary.UserStrings.Add(resolvedText);
        stack.Add($"str:{resolvedText}");
        return true;
    }

    private static bool TryHandleStaticField(
        OpCode opcode,
        int metadataToken,
        MetadataReader reader,
        List<string> stack,
        IlSummary summary,
        IReadOnlyDictionary<string, string> staticFieldValues
    )
    {
        if ((opcode != OpCodes.Ldsfld && opcode != OpCodes.Ldsflda && opcode != OpCodes.Stsfld) || metadataToken == 0)
        {
            return false;
        }

        string fieldName;
        try
        {
            fieldName = MetadataHelpers.ResolveEntityName(MetadataTokens.EntityHandle(metadataToken), reader);
        }
        catch
        {
            return false;
        }

        if (opcode == OpCodes.Stsfld)
        {
            if (stack.Count > 0)
            {
                string value = stack[^1];
                stack.RemoveAt(stack.Count - 1);
                summary.StaticFieldWrites[fieldName] = value;
            }
            return true;
        }

        if (staticFieldValues.TryGetValue(fieldName, out var resolvedValue))
        {
            stack.Add(resolvedValue);
        }
        else
        {
            stack.Add($"field:{fieldName}");
        }
        return true;
    }

    private static bool TryHandleKnownMethodReturn(
        string target,
        List<string> stack,
        IlSummary summary,
        IReadOnlyDictionary<string, string> knownMethodReturns
    )
    {
        if (!knownMethodReturns.TryGetValue(target, out var resolvedText) || string.IsNullOrWhiteSpace(resolvedText))
        {
            return false;
        }
        summary.UserStrings.Add(resolvedText);
        stack.Clear();
        stack.Add($"str:{resolvedText}");
        return true;
    }

    private static bool TryHandleEncodingGetString(string target, List<string> stack, IlSummary summary)
    {
        if (!target.EndsWith(".GetString", StringComparison.Ordinal))
        {
            return false;
        }
        if (!TryPopPrefixedValue(stack, "bytes:", out var bytesToken))
        {
            return false;
        }
        string encodingName = "utf-8";
        if (TryPopPrefixedValue(stack, "encoding:", out var explicitEncoding))
        {
            encodingName = explicitEncoding;
        }
        if (!TryDecodeBytesToken(bytesToken, encodingName, out var decodedText))
        {
            stack.Add($"bytes:{bytesToken}");
            return true;
        }
        summary.UserStrings.Add(decodedText);
        stack.Add($"str:{decodedText}");
        return true;
    }

    private static bool TryHandleBase64Decode(string target, List<string> stack, IlSummary summary)
    {
        if (!string.Equals(target, "System.Convert.FromBase64String", StringComparison.Ordinal))
        {
            return false;
        }
        if (!TryPopPrefixedValue(stack, "str:", out var encoded))
        {
            return false;
        }
        try
        {
            byte[] raw = Convert.FromBase64String(encoded);
            stack.Add($"bytes:{Convert.ToBase64String(raw)}");
            if (TryDecodeInterestingText(raw, out var decodedText))
            {
                summary.UserStrings.Add(decodedText);
            }
            return true;
        }
        catch
        {
            stack.Add($"call:{target}");
            return true;
        }
    }

    private static bool TryHandleStringConcat(string target, List<string> stack)
    {
        if (!string.Equals(target, "System.String.Concat", StringComparison.Ordinal))
        {
            return false;
        }
        var parts = new List<string>();
        while (TryPopPrefixedValue(stack, "str:", out var part) && parts.Count < 8)
        {
            parts.Add(part);
        }
        if (parts.Count < 2)
        {
            for (int index = parts.Count - 1; index >= 0; index--)
            {
                stack.Add($"str:{parts[index]}");
            }
            return false;
        }
        parts.Reverse();
        stack.Add($"str:{string.Concat(parts)}");
        return true;
    }

    private static bool TryHandleManifestResourceAccess(string target, List<string> stack, IlSummary summary)
    {
        if (!target.EndsWith(".GetManifestResourceStream", StringComparison.Ordinal))
        {
            return false;
        }
        string? resourceName = null;
        if (TryPopPrefixedValue(stack, "str:", out var literalName))
        {
            resourceName = literalName;
        }
        if (stack.Count > 0 && string.Equals(stack[^1], "assembly", StringComparison.Ordinal))
        {
            stack.RemoveAt(stack.Count - 1);
        }
        if (resourceName is null)
        {
            stack.Add($"call:{target}");
            return true;
        }
        summary.ResourceNames.Add(resourceName);
        stack.Add($"resource:{resourceName}");
        return true;
    }

    private static bool TryHandleStreamReaderCtor(string target, List<string> stack)
    {
        if (!target.EndsWith("System.IO.StreamReader..ctor", StringComparison.Ordinal))
        {
            return false;
        }
        TryPopPrefixedValue(stack, "encoding:", out _);
        if (!TryPopPrefixedValue(stack, "resource:", out var resourceName))
        {
            if (TryPopPrefixedValue(stack, "streambytes:", out var streamBytes))
            {
                stack.Add($"readerbytes:{streamBytes}");
                return true;
            }
            return false;
        }
        stack.Add($"reader:{resourceName}");
        return true;
    }

    private static bool TryHandleMemoryStreamCtor(string target, List<string> stack)
    {
        if (!target.EndsWith("System.IO.MemoryStream..ctor", StringComparison.Ordinal))
        {
            return false;
        }
        if (!TryPopPrefixedValue(stack, "bytes:", out var bytesToken))
        {
            return false;
        }
        stack.Add($"streambytes:{bytesToken}");
        return true;
    }

    private static bool TryHandleCompressionStreamCtor(string target, List<string> stack, IlSummary summary)
    {
        string? algorithm = target switch
        {
            "System.IO.Compression.GZipStream..ctor" => "gzip",
            "System.IO.Compression.DeflateStream..ctor" => "deflate",
            _ => null,
        };
        if (algorithm is null)
        {
            return false;
        }
        if (!TryPopPrefixedValue(stack, "int:", out var modeValue) || !int.TryParse(modeValue, out var compressionMode))
        {
            return false;
        }
        if (!TryPopPrefixedValue(stack, "streambytes:", out var compressedBytes))
        {
            return false;
        }
        if (compressionMode != 0)
        {
            stack.Add($"streambytes:{compressedBytes}");
            return true;
        }
        if (!TryInflateBytesToken(compressedBytes, algorithm, out var inflatedBytes))
        {
            stack.Add($"streambytes:{compressedBytes}");
            return true;
        }
        if (TryDecodeInterestingText(inflatedBytes, out var decodedText))
        {
            summary.UserStrings.Add(decodedText);
        }
        stack.Add($"streambytes:{Convert.ToBase64String(inflatedBytes)}");
        return true;
    }

    private static bool TryHandleReadToEnd(
        string target,
        List<string> stack,
        IlSummary summary,
        IReadOnlyDictionary<string, string> resourceTextByName
    )
    {
        if (!target.EndsWith(".ReadToEnd", StringComparison.Ordinal))
        {
            return false;
        }
        if (TryPopPrefixedValue(stack, "readerbytes:", out var readerBytes))
        {
            if (TryDecodeBytesToken(readerBytes, "utf-8", out var decodedText))
            {
                summary.UserStrings.Add(decodedText);
                stack.Add($"str:{decodedText}");
            }
            else
            {
                stack.Add($"readerbytes:{readerBytes}");
            }
            return true;
        }
        if (!TryPopPrefixedValue(stack, "reader:", out var resourceName))
        {
            return false;
        }
        if (!TryResolveResourceText(resourceName, resourceTextByName, out var resolvedText))
        {
            stack.Add($"call:{target}");
            return true;
        }
        summary.ResourceNames.Add(resourceName);
        summary.UserStrings.Add(resolvedText);
        stack.Add($"str:{resolvedText}");
        return true;
    }

    private static bool TryHandleStringBuilderCtor(
        string target,
        List<string> stack,
        Dictionary<string, string> builderStates,
        ref int nextBuilderId
    )
    {
        if (!target.EndsWith("System.Text.StringBuilder..ctor", StringComparison.Ordinal))
        {
            return false;
        }
        string initial = "";
        if (TryPopPrefixedValue(stack, "str:", out var literal))
        {
            initial = literal;
        }
        stack.Clear();
        string builderId = $"b{nextBuilderId++}";
        builderStates[builderId] = initial;
        stack.Add($"builderref:{builderId}");
        return true;
    }

    private static bool TryHandleStringBuilderAppend(
        string target,
        List<string> stack,
        Dictionary<string, string> builderStates
    )
    {
        if (!target.EndsWith("System.Text.StringBuilder.Append", StringComparison.Ordinal))
        {
            return false;
        }
        if (!TryPopPrefixedValue(stack, "str:", out var appended) || !TryPopPrefixedValue(stack, "builderref:", out var builderId))
        {
            return false;
        }
        string current = builderStates.TryGetValue(builderId, out var existing) ? existing : "";
        builderStates[builderId] = current + appended;
        stack.Add($"builderref:{builderId}");
        return true;
    }

    private static bool TryHandleStringBuilderToString(
        string target,
        List<string> stack,
        Dictionary<string, string> builderStates,
        IlSummary summary
    )
    {
        if (!target.EndsWith("System.Text.StringBuilder.ToString", StringComparison.Ordinal)
            && !target.EndsWith("System.Object.ToString", StringComparison.Ordinal))
        {
            return false;
        }
        if (!TryPopPrefixedValue(stack, "builderref:", out var builderId))
        {
            return false;
        }
        string current = builderStates.TryGetValue(builderId, out var existing) ? existing : "";
        if (LooksInterestingText(current))
        {
            summary.UserStrings.Add(current);
        }
        stack.Add($"str:{current}");
        return true;
    }

    private static bool TryHandleDisposeCall(string target, List<string> stack)
    {
        if (!target.EndsWith(".Dispose", StringComparison.Ordinal))
        {
            return false;
        }
        if (stack.Count > 0 && (
            stack[^1].StartsWith("reader", StringComparison.Ordinal)
            || stack[^1].StartsWith("streambytes:", StringComparison.Ordinal)
            || stack[^1].StartsWith("resource:", StringComparison.Ordinal)
            || stack[^1].StartsWith("call:", StringComparison.Ordinal)
            || stack[^1].StartsWith("field:", StringComparison.Ordinal)))
        {
            stack.RemoveAt(stack.Count - 1);
        }
        return true;
    }

    private static bool TryPopDelegate(List<string> stack, out string delegateTarget)
    {
        delegateTarget = string.Empty;
        if (!TryPopPrefixedValue(stack, "delegate:", out var value))
        {
            return false;
        }
        delegateTarget = value;
        return true;
    }

    private static bool TryPopPrefixedValue(List<string> stack, string prefix, out string value)
    {
        value = string.Empty;
        if (stack.Count == 0)
        {
            return false;
        }
        string top = stack[^1];
        if (!top.StartsWith(prefix, StringComparison.Ordinal))
        {
            return false;
        }
        value = top[prefix.Length..];
        stack.RemoveAt(stack.Count - 1);
        return true;
    }

    private static bool TryResolveResourceText(
        string resourceName,
        IReadOnlyDictionary<string, string> resourceTextByName,
        out string text
    )
    {
        if (resourceTextByName.TryGetValue(resourceName, out text!))
        {
            return true;
        }
        foreach (var item in resourceTextByName)
        {
            if (item.Key.EndsWith(resourceName, StringComparison.OrdinalIgnoreCase))
            {
                text = item.Value;
                return true;
            }
        }
        text = string.Empty;
        return false;
    }

    private static bool TryDecodeInterestingText(byte[] raw, out string decodedText)
    {
        decodedText = string.Empty;
        foreach (var encoding in new[] { Encoding.UTF8, Encoding.Unicode, Encoding.BigEndianUnicode, Encoding.ASCII, Encoding.Latin1 })
        {
            try
            {
                string candidate = encoding.GetString(raw).Trim('\0');
                    if (LooksInterestingText(candidate))
                    {
                        decodedText = candidate;
                        return true;
                    }
            }
            catch
            {
                // Ignore decode failures.
            }
        }
        return false;
    }

    private static bool TryDecodeBytesToken(string bytesToken, string encodingName, out string decodedText)
    {
        decodedText = string.Empty;
        try
        {
            byte[] raw = Convert.FromBase64String(bytesToken);
            Encoding encoding = encodingName.ToLowerInvariant() switch
            {
                "utf-16le" => Encoding.Unicode,
                "utf-16be" => Encoding.BigEndianUnicode,
                "ascii" => Encoding.ASCII,
                "latin-1" => Encoding.Latin1,
                _ => Encoding.UTF8,
            };
            string candidate = encoding.GetString(raw).Trim('\0');
            if (!LooksInterestingText(candidate))
            {
                return false;
            }
            decodedText = candidate;
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static bool TryInflateBytesToken(string bytesToken, string algorithm, out byte[] inflatedBytes)
    {
        inflatedBytes = Array.Empty<byte>();
        try
        {
            byte[] compressed = Convert.FromBase64String(bytesToken);
            using var source = new MemoryStream(compressed, writable: false);
            using Stream inflater = algorithm == "gzip"
                ? new GZipStream(source, CompressionMode.Decompress, leaveOpen: false)
                : new DeflateStream(source, CompressionMode.Decompress, leaveOpen: false);
            using var destination = new MemoryStream();
            inflater.CopyTo(destination);
            inflatedBytes = destination.ToArray();
            return inflatedBytes.Length > 0;
        }
        catch
        {
            return false;
        }
    }

    private static bool TryGetLocalIndex(OpCode opcode, byte[] il, int operandOffset, out int localIndex)
    {
        localIndex = -1;
        if (opcode == OpCodes.Ldloc_0 || opcode == OpCodes.Stloc_0)
        {
            localIndex = 0;
            return true;
        }
        if (opcode == OpCodes.Ldloc_1 || opcode == OpCodes.Stloc_1)
        {
            localIndex = 1;
            return true;
        }
        if (opcode == OpCodes.Ldloc_2 || opcode == OpCodes.Stloc_2)
        {
            localIndex = 2;
            return true;
        }
        if (opcode == OpCodes.Ldloc_3 || opcode == OpCodes.Stloc_3)
        {
            localIndex = 3;
            return true;
        }
        if (opcode == OpCodes.Ldloc_S || opcode == OpCodes.Stloc_S || opcode == OpCodes.Ldloca_S)
        {
            localIndex = il[operandOffset];
            return true;
        }
        if ((opcode == OpCodes.Ldloc || opcode == OpCodes.Stloc || opcode == OpCodes.Ldloca) && operandOffset + 1 < il.Length)
        {
            localIndex = BitConverter.ToUInt16(il, operandOffset);
            return true;
        }
        return false;
    }

    private static bool LooksInterestingText(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length < 4)
        {
            return false;
        }
        return value.Any(ch => char.IsLetter(ch));
    }

    private static bool IsStoreLocal(OpCode opcode)
    {
        return opcode == OpCodes.Stloc_0
            || opcode == OpCodes.Stloc_1
            || opcode == OpCodes.Stloc_2
            || opcode == OpCodes.Stloc_3
            || opcode == OpCodes.Stloc_S
            || opcode == OpCodes.Stloc;
    }

    private static bool TryGetIntConstant(OpCode opcode, byte[] il, int operandOffset, out int value)
    {
        value = 0;
        if (opcode == OpCodes.Ldc_I4_M1)
        {
            value = -1;
            return true;
        }
        if (opcode == OpCodes.Ldc_I4_0 || opcode == OpCodes.Ldc_I4_1 || opcode == OpCodes.Ldc_I4_2
            || opcode == OpCodes.Ldc_I4_3 || opcode == OpCodes.Ldc_I4_4 || opcode == OpCodes.Ldc_I4_5
            || opcode == OpCodes.Ldc_I4_6 || opcode == OpCodes.Ldc_I4_7 || opcode == OpCodes.Ldc_I4_8)
        {
            value = opcode.Value - OpCodes.Ldc_I4_0.Value;
            return true;
        }
        if (opcode == OpCodes.Ldc_I4_S)
        {
            value = unchecked((sbyte)il[operandOffset]);
            return true;
        }
        if (opcode == OpCodes.Ldc_I4 && operandOffset + 3 < il.Length)
        {
            value = BitConverter.ToInt32(il, operandOffset);
            return true;
        }
        return false;
    }

    private static Dictionary<ushort, OpCode> BuildOpcodeMap()
    {
        var map = new Dictionary<ushort, OpCode>();
        foreach (var field in typeof(OpCodes).GetFields(BindingFlags.Public | BindingFlags.Static))
        {
            if (field.GetValue(null) is OpCode opcode)
            {
                map[(ushort)opcode.Value] = opcode;
            }
        }
        return map;
    }
}

static class MetadataHelpers
{
    public static string ResolveMethodName(
        MethodDefinitionHandle handle,
        MetadataReader reader,
        IReadOnlyDictionary<TypeDefinitionHandle, string> typeNames)
    {
        foreach (var typeHandle in reader.TypeDefinitions)
        {
            var typeDefinition = reader.GetTypeDefinition(typeHandle);
            if (!typeNames.TryGetValue(typeHandle, out var typeName))
            {
                continue;
            }
            foreach (var methodHandle in typeDefinition.GetMethods())
            {
                if (methodHandle == handle)
                {
                    var methodDefinition = reader.GetMethodDefinition(methodHandle);
                    return $"{typeName}.{reader.GetString(methodDefinition.Name)}";
                }
            }
        }
        return "<entrypoint>";
    }

    public static string ResolveEntityName(EntityHandle handle, MetadataReader reader)
    {
        return handle.Kind switch
        {
            HandleKind.TypeReference => ResolveTypeReference((TypeReferenceHandle)handle, reader),
            HandleKind.TypeDefinition => ResolveTypeDefinition((TypeDefinitionHandle)handle, reader),
            HandleKind.FieldDefinition => ResolveFieldDefinition((FieldDefinitionHandle)handle, reader),
            HandleKind.MemberReference => ResolveMemberReference((MemberReferenceHandle)handle, reader),
            HandleKind.MethodDefinition => ResolveMethodDefinition((MethodDefinitionHandle)handle, reader),
            _ => handle.Kind.ToString(),
        };
    }

    private static string ResolveTypeDefinition(TypeDefinitionHandle handle, MetadataReader reader)
    {
        var definition = reader.GetTypeDefinition(handle);
        string ns = reader.GetString(definition.Namespace);
        string name = reader.GetString(definition.Name);
        return string.IsNullOrWhiteSpace(ns) ? name : $"{ns}.{name}";
    }

    private static string ResolveTypeReference(TypeReferenceHandle handle, MetadataReader reader)
    {
        var reference = reader.GetTypeReference(handle);
        string ns = reader.GetString(reference.Namespace);
        string name = reader.GetString(reference.Name);
        return string.IsNullOrWhiteSpace(ns) ? name : $"{ns}.{name}";
    }

    private static string ResolveMemberReference(MemberReferenceHandle handle, MetadataReader reader)
    {
        var reference = reader.GetMemberReference(handle);
        string parent = ResolveEntityName(reference.Parent, reader);
        string name = reader.GetString(reference.Name);
        return $"{parent}.{name}";
    }

    private static string ResolveFieldDefinition(FieldDefinitionHandle handle, MetadataReader reader)
    {
        string fieldName = reader.GetString(reader.GetFieldDefinition(handle).Name);
        foreach (var typeHandle in reader.TypeDefinitions)
        {
            var definition = reader.GetTypeDefinition(typeHandle);
            foreach (var fieldHandle in definition.GetFields())
            {
                if (fieldHandle == handle)
                {
                    return $"{ResolveTypeDefinition(typeHandle, reader)}.{fieldName}";
                }
            }
        }
        return fieldName;
    }

    private static string ResolveMethodDefinition(MethodDefinitionHandle handle, MetadataReader reader)
    {
        string methodName = reader.GetString(reader.GetMethodDefinition(handle).Name);
        foreach (var typeHandle in reader.TypeDefinitions)
        {
            var definition = reader.GetTypeDefinition(typeHandle);
            foreach (var methodHandle in definition.GetMethods())
            {
                if (methodHandle == handle)
                {
                    return $"{ResolveTypeDefinition(typeHandle, reader)}.{methodName}";
                }
            }
        }
        return methodName;
    }
}

static class ResourceHelpers
{
    public static List<ExtractedResource> ExtractEmbeddedResources(PEReader peReader, MetadataReader reader)
    {
        var results = new List<ExtractedResource>();
        var corHeader = peReader.PEHeaders.CorHeader;
        if (corHeader is null || corHeader.ResourcesDirectory.Size <= 0 || corHeader.ResourcesDirectory.RelativeVirtualAddress <= 0)
        {
            return results;
        }

        byte[] resourceRoot;
        try
        {
            resourceRoot = peReader.GetSectionData(corHeader.ResourcesDirectory.RelativeVirtualAddress)
                .GetContent(0, corHeader.ResourcesDirectory.Size)
                .ToArray();
        }
        catch
        {
            return results;
        }

        foreach (var handle in reader.ManifestResources)
        {
            var resource = reader.GetManifestResource(handle);
            if (!resource.Implementation.IsNil)
            {
                continue;
            }

            string name = reader.GetString(resource.Name);
            int offset = checked((int)resource.Offset);
            if (offset < 0 || offset + 4 > resourceRoot.Length)
            {
                continue;
            }

            int size = BitConverter.ToInt32(resourceRoot, offset);
            int start = offset + 4;
            if (size < 0 || start + size > resourceRoot.Length)
            {
                continue;
            }

            byte[] payload = resourceRoot.Skip(start).Take(size).ToArray();
            string? encoding = null;
            string? textPreview = null;
            string? decodedTextPreview = null;
            List<ExtractedResourceEntry>? entries = null;
            if (TryDecodeTextPayload(payload, out var text, out var textEncoding))
            {
                encoding = textEncoding;
                textPreview = TruncatePreview(text);
                if (TryDecodeBase64Text(text, out var decodedText, out _))
                {
                    decodedTextPreview = TruncatePreview(decodedText);
                }
            }
            else if (TryExtractResourcesEntries(payload, out var extractedEntries))
            {
                encoding = ".resources";
                entries = extractedEntries;
            }

            results.Add(new ExtractedResource(name, size, encoding, textPreview, decodedTextPreview, entries));
        }

        return results;
    }

    private static bool TryExtractResourcesEntries(byte[] payload, out List<ExtractedResourceEntry> entries)
    {
        entries = new List<ExtractedResourceEntry>();
        try
        {
            using var stream = new MemoryStream(payload, writable: false);
            using var reader = new ResourceReader(stream);
            var enumerator = reader.GetEnumerator();
            while (enumerator.MoveNext())
            {
                if (enumerator.Key is not string name || string.IsNullOrWhiteSpace(name))
                {
                    continue;
                }
                reader.GetResourceData(name, out var typeName, out var data);
                string? textPreview = null;
                string? decodedTextPreview = null;
                if (string.Equals(typeName, "ResourceTypeCode.String", StringComparison.Ordinal))
                {
                    if (TryDecodeResourceReaderString(data, out var text))
                    {
                        textPreview = TruncatePreview(text);
                        if (TryDecodeBase64Text(text, out var decodedText, out _))
                        {
                            decodedTextPreview = TruncatePreview(decodedText);
                        }
                    }
                }
                else if (
                    string.Equals(typeName, "ResourceTypeCode.ByteArray", StringComparison.Ordinal)
                    || string.Equals(typeName, "ResourceTypeCode.Stream", StringComparison.Ordinal)
                )
                {
                    if (TryUnwrapLengthPrefixedBlob(data, out var raw) && TryDecodeTextPayload(raw, out var text, out _))
                    {
                        textPreview = TruncatePreview(text);
                        if (TryDecodeBase64Text(text, out var decodedText, out _))
                        {
                            decodedTextPreview = TruncatePreview(decodedText);
                        }
                    }
                }

                entries.Add(new ExtractedResourceEntry(name, typeName, textPreview, decodedTextPreview));
            }
        }
        catch
        {
            entries = new List<ExtractedResourceEntry>();
            return false;
        }
        return entries.Count > 0;
    }

    private static bool TryDecodeTextPayload(byte[] payload, out string text, out string encodingName)
    {
        text = string.Empty;
        encodingName = string.Empty;
        foreach (var (encoding, name) in new (Encoding Encoding, string Name)[]
        {
            (new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true), "utf-8"),
            (new UnicodeEncoding(false, true, true), "utf-16le"),
            (new UnicodeEncoding(true, true, true), "utf-16be"),
            (Encoding.ASCII, "ascii"),
            (Encoding.Latin1, "latin-1"),
        })
        {
            try
            {
                string candidate = encoding.GetString(payload).Trim('\0');
                if (IsUsefulText(candidate))
                {
                    text = candidate;
                    encodingName = name;
                    return true;
                }
            }
            catch
            {
                // Ignore invalid decodes.
            }
        }
        return false;
    }

    private static bool TryDecodeResourceReaderString(byte[] data, out string text)
    {
        text = string.Empty;
        if (!TryRead7BitEncodedInt(data, out var byteLength, out var offset) || byteLength < 0)
        {
            return false;
        }
        if (offset + byteLength > data.Length)
        {
            return false;
        }
        try
        {
            string candidate = Encoding.UTF8.GetString(data, offset, byteLength).Trim('\0');
            if (!IsUsefulText(candidate))
            {
                return false;
            }
            text = candidate;
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static bool TryUnwrapLengthPrefixedBlob(byte[] data, out byte[] raw)
    {
        raw = Array.Empty<byte>();
        if (data.Length < 4)
        {
            return false;
        }
        int expected = BitConverter.ToInt32(data, 0);
        if (expected < 0 || expected > data.Length - 4)
        {
            return false;
        }
        raw = data.Skip(4).Take(expected).ToArray();
        return true;
    }

    private static bool TryRead7BitEncodedInt(byte[] data, out int value, out int bytesRead)
    {
        value = 0;
        bytesRead = 0;
        int shift = 0;
        while (bytesRead < data.Length && bytesRead < 5)
        {
            byte current = data[bytesRead++];
            value |= (current & 0x7F) << shift;
            if ((current & 0x80) == 0)
            {
                return true;
            }
            shift += 7;
        }
        value = 0;
        bytesRead = 0;
        return false;
    }

    private static bool TryDecodeBase64Text(string text, out string decodedText, out string encodingName)
    {
        decodedText = string.Empty;
        encodingName = string.Empty;
        string normalized = new string(text.Where(ch => !char.IsWhiteSpace(ch)).ToArray());
        if (normalized.Length < 12 || normalized.Length % 4 != 0)
        {
            return false;
        }
        try
        {
            byte[] payload = Convert.FromBase64String(normalized);
            return TryDecodeTextPayload(payload, out decodedText, out encodingName);
        }
        catch
        {
            return false;
        }
    }

    private static bool IsUsefulText(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length < 4 || !value.Any(ch => char.IsLetter(ch)))
        {
            return false;
        }
        int printable = value.Count(ch => ch == '\r' || ch == '\n' || ch == '\t' || !char.IsControl(ch));
        return printable * 1.0 / value.Length >= 0.9;
    }

    private static string TruncatePreview(string value)
    {
        string normalized = value.Replace("\r\n", "\n").Trim();
        const int MaxLength = 1200;
        if (normalized.Length <= MaxLength)
        {
            return normalized;
        }
        return normalized[..MaxLength] + "...";
    }
}

sealed record InputPayload(string? AssemblyBase64);

sealed record MethodWorkItem(
    string TypeName,
    string MethodName,
    string FullMethodName,
    byte[] IlBytes
);

sealed record WorkerResponse(
    bool Ok,
    string? Error,
    string? AssemblyName = null,
    string? ModuleName = null,
    string? MetadataVersion = null,
    string? EntryPoint = null,
    List<string>? Types = null,
    List<string>? Methods = null,
    List<string>? References = null,
    List<string>? Resources = null,
    List<string>? UserStrings = null,
    List<string>? SuspiciousReferences = null,
    List<string>? ProxyMethods = null,
    List<MethodSummary>? MethodSummaries = null,
    List<ExtractedResource>? EmbeddedResources = null
);

sealed record MethodSummary(
    string FullName,
    string DeclaringType,
    string MethodName,
    string? ReturnString,
    string? ProxyTarget,
    List<string> CallTargets,
    List<string> UserStrings,
    List<string> ResourceNames,
    List<string> SuspiciousReferences,
    int InstructionCount,
    bool IsLikelyProxy
);

sealed record ExtractedResource(
    string Name,
    int Size,
    string? Encoding,
    string? TextPreview,
    string? DecodedTextPreview,
    List<ExtractedResourceEntry>? Entries
);

sealed record ExtractedResourceEntry(
    string Name,
    string? TypeName,
    string? TextPreview,
    string? DecodedTextPreview
);
