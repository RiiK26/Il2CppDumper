using System;
using System.Collections.Generic;

namespace Il2CppDumper
{
    /// <summary>
    /// Scans method disassembly bytes in PE (x86_64) to extract call references
    /// and string literal references for dump.cs comments.
    /// Uses raw byte buffer for zero-overhead, ultra-fast scanning.
    /// </summary>
    public class MethodXrefScanner
    {
        private readonly Il2Cpp il2Cpp;
        private readonly Metadata metadata;
        private readonly Dictionary<ulong, string> rvaToMethodName = new();
        private readonly Dictionary<ulong, string> vaToStringLiteral = new();
        private readonly byte[] rawBytes;

        public MethodXrefScanner(Il2Cpp il2Cpp, Metadata metadata)
        {
            this.il2Cpp = il2Cpp;
            this.metadata = metadata;
            this.rawBytes = il2Cpp.RawBytes;

            IndexMethods();
            IndexMetadataUsages();
        }

        private void IndexMethods()
        {
            if (metadata.imageDefs == null || metadata.typeDefs == null || metadata.methodDefs == null) return;

            foreach (var imageDef in metadata.imageDefs)
            {
                var imageName = metadata.GetStringFromIndex(imageDef.nameIndex);
                var typeEnd = imageDef.typeStart + imageDef.typeCount;
                for (int typeDefIndex = imageDef.typeStart; typeDefIndex < typeEnd; typeDefIndex++)
                {
                    if (typeDefIndex >= metadata.typeDefs.Length) break;
                    var typeDef = metadata.typeDefs[typeDefIndex];
                    var methodEnd = typeDef.methodStart + typeDef.method_count;
                    for (int i = typeDef.methodStart; i < methodEnd; i++)
                    {
                        if (i >= metadata.methodDefs.Length) break;
                        var mDef = metadata.methodDefs[i];
                        var ptr = il2Cpp.GetMethodPointer(imageName, mDef);
                        if (ptr == 0) continue;
                        var rva = il2Cpp.GetRVA(ptr);
                        if (rva == 0 || rvaToMethodName.ContainsKey(rva)) continue;

                        var mName = metadata.GetStringFromIndex(mDef.nameIndex);
                        if (!string.IsNullOrEmpty(mName))
                        {
                            rvaToMethodName[rva] = mName;
                        }
                    }
                }
            }
        }

        private void IndexMetadataUsages()
        {
            if (il2Cpp.metadataUsages == null || metadata.stringLiterals == null) return;

            try
            {
                for (int i = 0; i < il2Cpp.metadataUsages.Length; i++)
                {
                    var metadataValue = il2Cpp.metadataUsages[i];
                    var encodedToken = (uint)metadataValue;
                    var usage = metadata.GetEncodedIndexTypeForVersion(encodedToken);
                    if ((Il2CppMetadataUsage)usage == Il2CppMetadataUsage.kIl2CppMetadataUsageStringLiteral)
                    {
                        var decodedIndex = metadata.GetDecodedMethodIndex(encodedToken);
                        if (decodedIndex < metadata.stringLiterals.Length)
                        {
                            var va = il2Cpp.MapRTVA((ulong)i * (ulong)il2Cpp.PointerSize);
                            var str = metadata.GetStringLiteralFromIndex(decodedIndex);
                            if (!string.IsNullOrEmpty(str) && va > 0 && !vaToStringLiteral.ContainsKey(va))
                            {
                                vaToStringLiteral[va] = str;
                            }
                        }
                    }
                }
            }
            catch { }
        }

        public (List<string> calls, List<string> strings) ScanMethod(ulong methodPointer, int maxBytes = 96)
        {
            if (methodPointer == 0 || rawBytes == null) return (null, null);

            List<string> calls = null;
            List<string> strings = null;

            try
            {
                var fileOffset = il2Cpp.MapVATR(methodPointer);
                if (fileOffset <= 0 || fileOffset >= (ulong)rawBytes.Length) return (null, null);

                int offset = (int)fileOffset;
                int limit = Math.Min(maxBytes, rawBytes.Length - offset);
                if (limit < 5) return (null, null);

                // Fast linear scan for x86_64
                for (int i = 0; i < limit - 4; i++)
                {
                    byte b = rawBytes[offset + i];

                    // RET (0xC3) -> stop scanning this function
                    if (b == 0xC3) break;

                    // CALL rel32 (0xE8 xx xx xx xx)
                    if (b == 0xE8 && i + 5 <= limit)
                    {
                        int rel = BitConverter.ToInt32(rawBytes, offset + i + 1);
                        ulong nextRip = methodPointer + (ulong)(i + 5);
                        ulong targetVa = nextRip + (ulong)rel;
                        ulong targetRva = il2Cpp.GetRVA(targetVa);

                        if (rvaToMethodName.TryGetValue(targetRva, out var targetName))
                        {
                            calls ??= new List<string>(4);
                            if (!calls.Contains(targetName) && calls.Count < 4)
                            {
                                calls.Add(targetName);
                            }
                        }
                    }

                    // LEA / MOV reg, [rip + disp32] (48/4C 8D/8B modrm disp32)
                    if ((b == 0x48 || b == 0x4C) && i + 7 <= limit && (rawBytes[offset + i + 1] == 0x8D || rawBytes[offset + i + 1] == 0x8B))
                    {
                        byte modrm = rawBytes[offset + i + 2];
                        if ((modrm & 0xC7) == 0x05) // [rip + disp32]
                        {
                            int disp = BitConverter.ToInt32(rawBytes, offset + i + 3);
                            ulong nextRip = methodPointer + (ulong)(i + 7);
                            ulong targetVa = nextRip + (ulong)disp;

                            if (vaToStringLiteral.TryGetValue(targetVa, out var lit))
                            {
                                strings ??= new List<string>(4);
                                if (!strings.Contains(lit) && strings.Count < 4)
                                {
                                    strings.Add(lit);
                                }
                            }
                        }
                    }
                }
            }
            catch { }

            return (calls, strings);
        }
    }
}
