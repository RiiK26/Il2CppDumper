using System;
using System.Collections.Generic;
using System.Linq;

namespace Il2CppDumper
{
    /// <summary>
    /// Performs context-aware semantic renaming for obfuscated types/enums
    /// and detects compiler-merged ICF (Identical Code Folding) / shared RVA stubs.
    /// </summary>
    public class SemanticDeobfuscator
    {
        private readonly Metadata metadata;
        private readonly Il2Cpp il2Cpp;
        private readonly Dictionary<ulong, int> rvaCounts = new();
        private readonly Dictionary<int, string> semanticTypeNames = new();

        public SemanticDeobfuscator(Metadata metadata, Il2Cpp il2Cpp)
        {
            this.metadata = metadata;
            this.il2Cpp = il2Cpp;

            IndexRvaStubs();
            AnalyzeSemanticContext();
        }

        private void IndexRvaStubs()
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
                        if (rva == 0) continue;

                        if (!rvaCounts.TryGetValue(rva, out var count))
                        {
                            rvaCounts[rva] = 1;
                        }
                        else
                        {
                            rvaCounts[rva] = count + 1;
                        }
                    }
                }
            }
        }

        private void AnalyzeSemanticContext()
        {
            if (metadata.typeDefs == null || metadata.fieldDefs == null || il2Cpp.types == null) return;

            // Map: typeDefIndex -> List of candidate field/property names that reference it
            var typeHints = new Dictionary<int, List<string>>();

            // Scan all fields in all types for usages of obfuscated types/enums
            for (int t = 0; t < metadata.typeDefs.Length; t++)
            {
                var typeDef = metadata.typeDefs[t];
                if (typeDef.field_count == 0) continue;

                var fieldEnd = typeDef.fieldStart + typeDef.field_count;
                for (int f = typeDef.fieldStart; f < fieldEnd; f++)
                {
                    if (f < 0 || f >= metadata.fieldDefs.Length) continue;
                    var fieldDef = metadata.fieldDefs[f];
                    if (fieldDef.typeIndex < 0 || fieldDef.typeIndex >= il2Cpp.types.Length) continue;

                    var fieldType = il2Cpp.types[fieldDef.typeIndex];
                    var rawFieldName = metadata.GetStringFromIndex(fieldDef.nameIndex);
                    if (NameDeobfuscator.IsObfuscated(rawFieldName)) continue;

                    // Clean field name like "weaponType", "gameState", "_state"
                    var cleanFieldName = rawFieldName.TrimStart('_', 'm', '_');
                    if (string.IsNullOrWhiteSpace(cleanFieldName) || cleanFieldName.Length < 3) continue;

                    // Check if fieldType points to a class/valuetype
                    if (fieldType.type == Il2CppTypeEnum.IL2CPP_TYPE_CLASS ||
                        fieldType.type == Il2CppTypeEnum.IL2CPP_TYPE_VALUETYPE)
                    {
                        var targetTypeDefIndex = (int)fieldType.data.klassIndex;
                        if (targetTypeDefIndex >= 0 && targetTypeDefIndex < metadata.typeDefs.Length)
                        {
                            var targetDef = metadata.typeDefs[targetTypeDefIndex];
                            var targetRawName = metadata.GetStringFromIndex(targetDef.nameIndex);
                            if (NameDeobfuscator.IsObfuscated(targetRawName))
                            {
                                if (!typeHints.TryGetValue(targetTypeDefIndex, out var list))
                                {
                                    list = new List<string>();
                                    typeHints[targetTypeDefIndex] = list;
                                }
                                list.Add(cleanFieldName);
                            }
                        }
                    }
                }
            }

            // Derive semantic names from most frequent clean usage hints
            foreach (var (typeDefIndex, hints) in typeHints)
            {
                var targetDef = metadata.typeDefs[typeDefIndex];
                var bestHint = hints.GroupBy(h => h, StringComparer.OrdinalIgnoreCase)
                                    .OrderByDescending(g => g.Count())
                                    .Select(g => g.Key)
                                    .FirstOrDefault();

                if (!string.IsNullOrEmpty(bestHint))
                {
                    // Capitalize first letter
                    var capitalized = char.ToUpperInvariant(bestHint[0]) + (bestHint.Length > 1 ? bestHint[1..] : "");
                    if (targetDef.IsEnum)
                    {
                        semanticTypeNames[typeDefIndex] = $"{capitalized}_Enum_{typeDefIndex}";
                    }
                    else if (targetDef.IsValueType)
                    {
                        semanticTypeNames[typeDefIndex] = $"{capitalized}_Struct_{typeDefIndex}";
                    }
                    else
                    {
                        semanticTypeNames[typeDefIndex] = $"{capitalized}_Class_{typeDefIndex}";
                    }
                }
            }
        }

        public string GetSharedStubComment(ulong rva)
        {
            if (rva == 0) return null;
            if (rvaCounts.TryGetValue(rva, out var count) && count >= 5)
            {
                return $"\t// [Compiler-Merged Stub / ICF: {count} methods share RVA 0x{rva:X}]\n";
            }
            return null;
        }

        public bool TryGetSemanticTypeName(int typeDefIndex, out string name)
        {
            return semanticTypeNames.TryGetValue(typeDefIndex, out name);
        }
    }
}
