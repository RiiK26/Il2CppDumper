using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Il2CppDumper
{
    public static class MetadataTableReconstructor
    {
        private const uint StandardMagic = 0xFAB11BAF;

        /// <summary>
        /// Checks if the header in the given metadata bytes is wiped, zeroed, or corrupted.
        /// </summary>
        public static bool IsHeaderWiped(byte[] data)
        {
            if (data == null || data.Length < 256)
                return false;

            uint magic = BitConverter.ToUInt32(data, 0);
            int version = BitConverter.ToInt32(data, 4);

            // If magic is not standard or version is 0
            if (magic == 0 && version == 0)
                return true;

            // If first 64 bytes are predominantly zeroes
            int zeroCount = 0;
            for (int i = 0; i < 64; i++)
            {
                if (data[i] == 0) zeroCount++;
            }
            if (zeroCount > 55)
                return true;

            // If critical header offsets are all zero
            uint strLitOff = BitConverter.ToUInt32(data, 8);
            uint strOff = BitConverter.ToUInt32(data, 16);
            uint typeDefOff = BitConverter.ToUInt32(data, 48);
            if (strLitOff == 0 && strOff == 0 && typeDefOff == 0)
                return true;

            return false;
        }

        /// <summary>
        /// Attempts to locate metadata tables by fingerprinting structure patterns and strings,
        /// and reconstructs a valid Il2CppGlobalMetadataHeader in-place.
        /// </summary>
        public static bool TryReconstruct(byte[] rawData, double? targetVersion, out byte[] reconstructed, out string info)
        {
            reconstructed = null;
            info = null;

            if (rawData == null || rawData.Length < 1024)
                return false;

            try
            {
                // 1. Locate the string table
                if (!TryLocateStringTable(rawData, out uint stringOffset, out uint stringSize, out var stringMap))
                    return false;

                // 2. Locate image definitions
                if (!TryLocateImageDefinitions(rawData, stringOffset, stringMap, out uint imagesOffset, out int imageCount, out int imageDefSize, out int totalTypeDefCount))
                    return false;

                // 3. Locate assembly definitions
                if (!TryLocateAssemblyDefinitions(rawData, stringOffset, stringMap, imageCount, out uint assembliesOffset, out int assemblyDefSize))
                {
                    // Fallback estimate if not found directly
                    assembliesOffset = 0;
                    assemblyDefSize = 68;
                }

                // 4. Locate type definitions
                if (!TryLocateTypeDefinitions(rawData, stringOffset, stringSize, imagesOffset, imageCount * imageDefSize, assembliesOffset, imageCount * assemblyDefSize, totalTypeDefCount, out uint typeDefsOffset, out int typeDefSize, out double detectedVersion))
                    return false;

                int finalVersion = targetVersion.HasValue ? (int)targetVersion.Value : (int)detectedVersion;
                if (finalVersion < 16 || finalVersion > 200)
                    finalVersion = 29; // default modern fallback

                // 5. Locate method definitions
                TryLocateMethodDefinitions(rawData, stringOffset, stringSize, typeDefsOffset, totalTypeDefCount, typeDefSize, out uint methodsOffset, out int methodsCount, out int methodDefSize);

                // 6. Build the reconstructed header
                var result = (byte[])rawData.Clone();
                using (var ms = new MemoryStream(result))
                using (var writer = new BinaryWriter(ms))
                {
                    writer.Write(StandardMagic); // sanity
                    writer.Write(finalVersion);   // version

                    // stringLiteralOffset, stringLiteralSize
                    writer.Write(0u);
                    writer.Write(0);

                    // stringLiteralDataOffset, stringLiteralDataSize
                    writer.Write(0u);
                    writer.Write(0);

                    // stringOffset, stringSize
                    writer.Write(stringOffset);
                    writer.Write((int)stringSize);

                    // eventsOffset, eventsSize
                    writer.Write(0u);
                    writer.Write(0);

                    // propertiesOffset, propertiesSize
                    writer.Write(0u);
                    writer.Write(0);

                    // methodsOffset, methodsSize
                    writer.Write(methodsOffset);
                    writer.Write(methodsCount * methodDefSize);

                    // parameterDefaultValuesOffset, parameterDefaultValuesSize
                    writer.Write(0u);
                    writer.Write(0);

                    // fieldDefaultValuesOffset, fieldDefaultValuesSize
                    writer.Write(0u);
                    writer.Write(0);

                    // fieldAndParameterDefaultValueDataOffset, size
                    writer.Write(0u);
                    writer.Write(0);

                    // fieldMarshaledSizesOffset, size
                    writer.Write(0u);
                    writer.Write(0);

                    // parametersOffset, parametersSize
                    writer.Write(0u);
                    writer.Write(0);

                    // fieldsOffset, fieldsSize
                    writer.Write(0u);
                    writer.Write(0);

                    // genericParametersOffset, genericParametersSize
                    writer.Write(0u);
                    writer.Write(0);

                    // genericParameterConstraintsOffset, genericParameterConstraintsSize
                    writer.Write(0u);
                    writer.Write(0);

                    // genericContainersOffset, genericContainersSize
                    writer.Write(0u);
                    writer.Write(0);

                    // nestedTypesOffset, nestedTypesSize
                    writer.Write(0u);
                    writer.Write(0);

                    // interfacesOffset, interfacesSize
                    writer.Write(0u);
                    writer.Write(0);

                    // vtableMethodsOffset, vtableMethodsSize
                    writer.Write(0u);
                    writer.Write(0);

                    // interfaceOffsetsOffset, interfaceOffsetsSize
                    writer.Write(0u);
                    writer.Write(0);

                    // typeDefinitionsOffset, typeDefinitionsSize
                    writer.Write(typeDefsOffset);
                    writer.Write(totalTypeDefCount * typeDefSize);

                    // imagesOffset, imagesSize
                    writer.Write(imagesOffset);
                    writer.Write(imageCount * imageDefSize);

                    // assembliesOffset, assembliesSize
                    writer.Write(assembliesOffset);
                    writer.Write(imageCount * assemblyDefSize);
                }

                info = $"Reconstructed wiped metadata header: v{finalVersion}, {imageCount} assemblies, {totalTypeDefCount} types (TypeDefs @ 0x{typeDefsOffset:X}, Strings @ 0x{stringOffset:X})";
                reconstructed = result;
                return true;
            }
            catch (Exception ex)
            {
                info = $"Header reconstruction failed: {ex.Message}";
                return false;
            }
        }

        private static bool TryLocateStringTable(byte[] data, out uint stringOffset, out uint stringSize, out Dictionary<string, uint> stringMap)
        {
            stringOffset = 0;
            stringSize = 0;
            stringMap = new Dictionary<string, uint>(StringComparer.Ordinal);

            // Targets to search for inside the string table
            string[] anchors = { "mscorlib.dll", "<Module>", "System", "UnityEngine" };
            int anchorPos = -1;

            foreach (var anchor in anchors)
            {
                var bytes = Encoding.ASCII.GetBytes(anchor + "\0");
                int idx = IndexOfSequence(data, bytes, 0);
                if (idx != -1)
                {
                    anchorPos = idx;
                    break;
                }
            }

            if (anchorPos == -1)
                return false;

            // Expand backwards to find string table start
            int start = anchorPos;
            int zeroStreakBack = 0;
            while (start > 256)
            {
                byte b = data[start - 1];
                if ((b >= 32 && b <= 126) || b == 9 || b == 10 || b == 13)
                {
                    zeroStreakBack = 0;
                    start--;
                }
                else if (b == 0)
                {
                    zeroStreakBack++;
                    if (zeroStreakBack > 2 && start <= 260)
                    {
                        start = 256;
                        break;
                    }
                    if (zeroStreakBack > 4)
                    {
                        start += zeroStreakBack;
                        break;
                    }
                    start--;
                }
                else
                {
                    break;
                }
            }

            // Align backwards to 4-byte boundary
            start -= (start % 4);
            if (start < 256)
                start = 256;

            stringOffset = (uint)start;

            // Expand forward to find string table end
            int end = anchorPos;
            int zeroStreakFwd = 0;
            int nonAsciiStreak = 0;
            while (end < data.Length)
            {
                byte b = data[end];
                if (b >= 32 && b <= 126)
                {
                    zeroStreakFwd = 0;
                    nonAsciiStreak = 0;
                    end++;
                }
                else if (b == 0)
                {
                    zeroStreakFwd++;
                    if (zeroStreakFwd > 4)
                    {
                        end -= zeroStreakFwd;
                        break;
                    }
                    end++;
                }
                else
                {
                    nonAsciiStreak++;
                    if (nonAsciiStreak > 3)
                    {
                        end -= nonAsciiStreak;
                        break;
                    }
                    end++;
                }
            }

            stringSize = (uint)(end - start);

            // Build dictionary of strings found within this range
            stringMap[""] = 0;
            int cur = start;
            while (cur < end)
            {
                while (cur < end && data[cur] == 0)
                    cur++;

                int sStart = cur;
                while (cur < end && data[cur] != 0)
                    cur++;

                if (cur > sStart)
                {
                    string str = Encoding.ASCII.GetString(data, sStart, cur - sStart);
                    uint relOffset = (uint)(sStart - start);
                    if (!stringMap.ContainsKey(str))
                        stringMap[str] = relOffset;
                }
            }

            return stringMap.Count > 0;
        }

        private static bool TryLocateImageDefinitions(byte[] data, uint stringOffset, Dictionary<string, uint> stringMap,
            out uint imagesOffset, out int imageCount, out int imageDefSize, out int totalTypeDefCount)
        {
            imagesOffset = 0;
            imageCount = 0;
            imageDefSize = 40; // Default size for v24.1+
            totalTypeDefCount = 0;

            uint mscorlibStrIdx = 0;
            if (stringMap.TryGetValue("mscorlib.dll", out var idx) ||
                stringMap.TryGetValue("mscorlib", out idx) ||
                stringMap.TryGetValue("System.Private.CoreLib.dll", out idx))
            {
                mscorlibStrIdx = idx;
            }
            else
            {
                return false;
            }

            int[] candidateSizes = { 40, 32, 28 };

            for (int p = 256; p <= data.Length - 128; p += 4)
            {
                if (BitConverter.ToUInt32(data, p) == mscorlibStrIdx &&
                    BitConverter.ToInt32(data, p + 4) == 0 &&   // assemblyIndex == 0
                    BitConverter.ToInt32(data, p + 8) == 0)     // typeStart == 0
                {
                    uint typeCount0 = BitConverter.ToUInt32(data, p + 12);
                    if (typeCount0 > 0 && typeCount0 < 50000)
                    {
                        foreach (var size in candidateSizes)
                        {
                            if (p + size + 16 <= data.Length)
                            {
                                int asmIdx1 = BitConverter.ToInt32(data, p + size + 4);
                                int typeStart1 = BitConverter.ToInt32(data, p + size + 8);
                                if (asmIdx1 == 1 && typeStart1 == (int)typeCount0)
                                {
                                    // Found images table!
                                    imagesOffset = (uint)p;
                                    imageDefSize = size;

                                    // Count total images
                                    int count = 0;
                                    int cur = p;
                                    int runningTypes = 0;
                                    while (cur + size <= data.Length)
                                    {
                                        int curAsm = BitConverter.ToInt32(data, cur + 4);
                                        int curTypeStart = BitConverter.ToInt32(data, cur + 8);
                                        uint curTypeCount = BitConverter.ToUInt32(data, cur + 12);

                                        if (curAsm != count || curTypeStart != runningTypes || curTypeCount > 100000)
                                            break;

                                        runningTypes += (int)curTypeCount;
                                        count++;
                                        cur += size;
                                    }

                                    imageCount = count;
                                    totalTypeDefCount = runningTypes;
                                    return true;
                                }
                            }
                        }
                    }
                }
            }

            return false;
        }

        private static bool TryLocateAssemblyDefinitions(byte[] data, uint stringOffset, Dictionary<string, uint> stringMap,
            int imageCount, out uint assembliesOffset, out int assemblyDefSize)
        {
            assembliesOffset = 0;
            assemblyDefSize = 68;

            uint mscorlibStrIdx = 0;
            if (stringMap.TryGetValue("mscorlib", out var idx) ||
                stringMap.TryGetValue("mscorlib.dll", out idx))
            {
                mscorlibStrIdx = idx;
            }

            int[] candidateSizes = { 68, 72, 64 };

            for (int p = 256; p <= data.Length - 128; p += 4)
            {
                if (BitConverter.ToInt32(data, p) == 0) // imageIndex == 0
                {
                    foreach (var size in candidateSizes)
                    {
                        if (p + size + 4 <= data.Length && BitConverter.ToInt32(data, p + size) == 1) // next imageIndex == 1
                        {
                            assembliesOffset = (uint)p;
                            assemblyDefSize = size;
                            return true;
                        }
                    }
                }
            }

            return false;
        }

        private static bool TryLocateTypeDefinitions(byte[] data, uint stringOffset, uint stringSize,
            uint imagesOffset, int imagesSize, uint assembliesOffset, int assembliesSize,
            int totalTypeDefCount, out uint typeDefsOffset, out int typeDefSize, out double detectedVersion)
        {
            typeDefsOffset = 0;
            typeDefSize = 88;
            detectedVersion = 29;

            // <Module> is always the first type definition in mscorlib
            int[] candidateSizes = { 88, 92, 100 }; // v27-v31 (88), v24.2-v24.5 (92), v24.1 (100)

            for (int p = 256; p <= data.Length - 200; p += 4)
            {
                // Skip if within images or assemblies table
                if (p >= imagesOffset && p < imagesOffset + imagesSize)
                    continue;
                if (assembliesOffset > 0 && p >= assembliesOffset && p < assembliesOffset + assembliesSize)
                    continue;

                uint nameIdx0 = BitConverter.ToUInt32(data, p);
                uint nsIdx0 = BitConverter.ToUInt32(data, p + 4);

                if (nameIdx0 < stringSize && nsIdx0 < stringSize)
                {
                    // Check if string at nameIdx0 is "<Module>"
                    int absName = (int)(stringOffset + nameIdx0);
                    if (absName + 8 <= data.Length &&
                        data[absName] == '<' && data[absName + 1] == 'M' &&
                        data[absName + 2] == 'o' && data[absName + 3] == 'd' &&
                        data[absName + 4] == 'u' && data[absName + 5] == 'l' &&
                        data[absName + 6] == 'e' && data[absName + 7] == '>')
                    {
                        foreach (var size in candidateSizes)
                        {
                            bool valid = true;
                            int checkCount = Math.Min(totalTypeDefCount > 0 ? totalTypeDefCount : 3, 10);
                            for (int t = 1; t < checkCount; t++)
                            {
                                int tp = p + t * size;
                                if (tp + 8 > data.Length) { valid = false; break; }
                                uint tName = BitConverter.ToUInt32(data, tp);
                                uint tNs = BitConverter.ToUInt32(data, tp + 4);
                                if (tName == 0 || tName >= stringSize || tNs >= stringSize)
                                {
                                    valid = false;
                                    break;
                                }
                            }

                            if (valid)
                            {
                                typeDefsOffset = (uint)p;
                                typeDefSize = size;
                                detectedVersion = size == 88 ? 29 : (size == 92 ? 24.3 : 24.1);
                                return true;
                            }
                        }
                    }
                }
            }

            return false;
        }

        private static void TryLocateMethodDefinitions(byte[] data, uint stringOffset, uint stringSize,
            uint typeDefsOffset, int typeDefCount, int typeDefSize,
            out uint methodsOffset, out int methodsCount, out int methodDefSize)
        {
            methodsOffset = 0;
            methodsCount = 0;
            methodDefSize = 32;

            int maxMethod = 0;
            for (int i = 0; i < typeDefCount; i++)
            {
                int p = (int)(typeDefsOffset + i * typeDefSize);
                if (p + 48 <= data.Length)
                {
                    // methodStart is at offset 44 (v24.2+) or 40
                    int methodStart = BitConverter.ToInt32(data, p + 44);
                    ushort methodCount = BitConverter.ToUInt16(data, p + 68);
                    if (methodStart >= 0 && methodCount > 0)
                    {
                        if (methodStart + methodCount > maxMethod)
                            maxMethod = methodStart + methodCount;
                    }
                }
            }

            methodsCount = maxMethod;

            // Search for first method definition
            for (int p = 256; p <= data.Length - 64; p += 4)
            {
                uint nameIdx = BitConverter.ToUInt32(data, p);
                if (nameIdx < stringSize && nameIdx > 0)
                {
                    int declType = BitConverter.ToInt32(data, p + 4);
                    int retType = BitConverter.ToInt32(data, p + 8);
                    if (declType >= 0 && declType < typeDefCount && retType >= 0)
                    {
                        methodsOffset = (uint)p;
                        return;
                    }
                }
            }
        }

        private static int IndexOfSequence(byte[] buffer, byte[] pattern, int startIndex)
        {
            int max = buffer.Length - pattern.Length;
            for (int i = startIndex; i <= max; i++)
            {
                bool match = true;
                for (int j = 0; j < pattern.Length; j++)
                {
                    if (buffer[i + j] != pattern[j])
                    {
                        match = false;
                        break;
                    }
                }
                if (match)
                    return i;
            }
            return -1;
        }
    }
}
