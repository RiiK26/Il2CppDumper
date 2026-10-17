using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Il2CppDumper
{
    public class CodeCluster
    {
        public ulong StartVA { get; set; }
        public ulong EndVA { get; set; }
        public int TotalCount { get; set; }
        public int ValidCodeCount { get; set; }
        public double Density => TotalCount > 0 ? (double)ValidCodeCount / TotalCount : 0;
    }

    public class CandidateRegistration
    {
        public ulong VA { get; set; }
        public double Score { get; set; }
        public string Reason { get; set; }
        public int MatchedFields { get; set; }
    }

    public class RegistrationPair
    {
        public ulong CodeRegVA { get; set; }
        public ulong MetaRegVA { get; set; }
        public double CodeScore { get; set; }
        public double MetaScore { get; set; }
        public double ProximityScore { get; set; }
        public double TotalScore => CodeScore + MetaScore + ProximityScore;
        public string Details { get; set; }
    }

    public static class PointerDensityScanner
    {
        public static bool Search(Il2Cpp il2Cpp, Metadata metadata, double densityThreshold = 0.80, int minClusterSize = 16)
        {
            int methodCount = metadata?.methodDefs != null ? metadata.methodDefs.Count(x => x.methodIndex >= 0) : 0;
            int typeDefsCount = metadata?.typeDefs != null ? metadata.typeDefs.Length : 0;
            int imageCount = metadata?.imageDefs != null ? metadata.imageDefs.Length : 0;

            var sectionHelper = il2Cpp.GetSectionHelper(methodCount, typeDefsCount, imageCount);
            if (sectionHelper?.Data == null || sectionHelper.Exec == null || sectionHelper.Data.Count == 0 || sectionHelper.Exec.Count == 0)
            {
                return false;
            }

            var dataSections = sectionHelper.Data;
            var execSections = sectionHelper.Exec;

            // 1. Detect function pointer clusters in data sections
            var clusters = FindCodePointerClusters(il2Cpp, dataSections, execSections, densityThreshold, minClusterSize);
            Console.WriteLine($"[+] PointerDensityScanner: Found {clusters.Count} code pointer clusters (density >= {densityThreshold:P0})");

            // 2. Discover candidate CodeRegistration structs
            var codeCandidates = FindCodeRegistrationCandidates(il2Cpp, dataSections, execSections, clusters, methodCount, imageCount, densityThreshold);

            // 3. Discover candidate MetadataRegistration structs
            var metaCandidates = FindMetadataRegistrationCandidates(il2Cpp, dataSections, typeDefsCount);

            // 4. Pair and score candidates by mutual proximity and structure score
            var pairs = BuildAndRankPairs(il2Cpp, codeCandidates, metaCandidates, dataSections, execSections, typeDefsCount);

            // 5. Test candidate pairs with AutoPlusInit
            var savedVersion = il2Cpp.Version;
            foreach (var pair in pairs)
            {
                try
                {
                    il2Cpp.Version = savedVersion;
                    if (il2Cpp.AutoPlusInit(pair.CodeRegVA, pair.MetaRegVA))
                    {
                        Console.WriteLine($"[+] PointerDensityScanner matched registration pair (Score: {pair.TotalScore:F0}):");
                        Console.WriteLine($"    CodeRegistration    : 0x{pair.CodeRegVA:X} (Score: {pair.CodeScore:F0})");
                        Console.WriteLine($"    MetadataRegistration: 0x{pair.MetaRegVA:X} (Score: {pair.MetaScore:F0})");
                        if (!string.IsNullOrEmpty(pair.Details))
                        {
                            Console.WriteLine($"    Details: {pair.Details}");
                        }
                        return true;
                    }
                }
                catch
                {
                    il2Cpp.Version = savedVersion;
                }
            }

            return false;
        }

        public static ulong FindCodeRegistration(Il2Cpp il2Cpp, SectionHelper sectionHelper, int methodCount, int imageCount, double densityThreshold = 0.80)
        {
            var dataSections = sectionHelper.Data;
            var execSections = sectionHelper.Exec;
            if (dataSections == null || execSections == null) return 0;

            var clusters = FindCodePointerClusters(il2Cpp, dataSections, execSections, densityThreshold, 16);
            var candidates = FindCodeRegistrationCandidates(il2Cpp, dataSections, execSections, clusters, methodCount, imageCount, densityThreshold);

            return candidates.Count > 0 ? candidates[0].VA : 0;
        }

        public static ulong FindMetadataRegistration(Il2Cpp il2Cpp, SectionHelper sectionHelper, int typeDefsCount, double densityThreshold = 0.80)
        {
            var dataSections = sectionHelper.Data;
            if (dataSections == null) return 0;

            var candidates = FindMetadataRegistrationCandidates(il2Cpp, dataSections, typeDefsCount);
            return candidates.Count > 0 ? candidates[0].VA : 0;
        }

        public static List<CodeCluster> FindCodePointerClusters(Il2Cpp il2Cpp, List<SearchSection> dataSections, List<SearchSection> execSections, double densityThreshold, int minClusterSize)
        {
            var clusters = new List<CodeCluster>();
            var ptrSize = (int)il2Cpp.PointerSize;

            foreach (var sec in dataSections)
            {
                var length = (int)Math.Min((ulong)int.MaxValue, sec.offsetEnd - sec.offset);
                if (length < ptrSize * minClusterSize) continue;

                il2Cpp.Position = sec.offset;
                var bytes = il2Cpp.ReadBytes(length);

                int clusterStartIdx = -1;
                int validInCluster = 0;
                int currentClusterLen = 0;
                int consecutiveGaps = 0;

                for (int i = 0; i <= length - ptrSize; i += ptrSize)
                {
                    ulong ptrVal = il2Cpp.Is32Bit
                        ? BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(i, 4))
                        : BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(i, 8));

                    bool isCode = IsInExec(ptrVal, execSections);

                    if (isCode)
                    {
                        if (clusterStartIdx < 0)
                        {
                            clusterStartIdx = i;
                            validInCluster = 1;
                            currentClusterLen = 1;
                            consecutiveGaps = 0;
                        }
                        else
                        {
                            validInCluster++;
                            currentClusterLen++;
                            consecutiveGaps = 0;
                        }
                    }
                    else
                    {
                        if (clusterStartIdx >= 0)
                        {
                            consecutiveGaps++;
                            currentClusterLen++;

                            double currentDensity = (double)validInCluster / currentClusterLen;
                            // Terminate cluster if too many consecutive non-code pointers or density drops below threshold
                            if (consecutiveGaps > 3 || currentDensity < densityThreshold)
                            {
                                int actualLen = currentClusterLen - consecutiveGaps;
                                if (actualLen >= minClusterSize && (double)validInCluster / actualLen >= densityThreshold)
                                {
                                    clusters.Add(new CodeCluster
                                    {
                                        StartVA = sec.address + (ulong)clusterStartIdx,
                                        EndVA = sec.address + (ulong)(clusterStartIdx + actualLen * ptrSize),
                                        TotalCount = actualLen,
                                        ValidCodeCount = validInCluster
                                    });
                                }

                                clusterStartIdx = -1;
                                validInCluster = 0;
                                currentClusterLen = 0;
                                consecutiveGaps = 0;
                            }
                        }
                    }
                }

                if (clusterStartIdx >= 0)
                {
                    int actualLen = currentClusterLen - consecutiveGaps;
                    if (actualLen >= minClusterSize && (double)validInCluster / actualLen >= densityThreshold)
                    {
                        clusters.Add(new CodeCluster
                        {
                            StartVA = sec.address + (ulong)clusterStartIdx,
                            EndVA = sec.address + (ulong)(clusterStartIdx + actualLen * ptrSize),
                            TotalCount = actualLen,
                            ValidCodeCount = validInCluster
                        });
                    }
                }
            }

            return clusters;
        }

        public static List<CandidateRegistration> FindCodeRegistrationCandidates(
            Il2Cpp il2Cpp,
            List<SearchSection> dataSections,
            List<SearchSection> execSections,
            List<CodeCluster> clusters,
            int expectedMethodCount,
            int expectedImageCount,
            double densityThreshold)
        {
            var candidates = new Dictionary<ulong, CandidateRegistration>();
            var ptrSize = il2Cpp.PointerSize;

            // Strategy 1: Cross-reference heads of code pointer clusters
            var clusterMap = new Dictionary<ulong, CodeCluster>();
            foreach (var c in clusters)
            {
                clusterMap[c.StartVA] = c;
            }

            foreach (var sec in dataSections)
            {
                var length = (int)Math.Min((ulong)int.MaxValue, sec.offsetEnd - sec.offset);
                if (length < (int)ptrSize * 2) continue;

                il2Cpp.Position = sec.offset;
                var bytes = il2Cpp.ReadBytes(length);

                for (int i = (int)ptrSize; i <= length - (int)ptrSize; i += (int)ptrSize)
                {
                    ulong ptrVal = il2Cpp.Is32Bit
                        ? BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(i, 4))
                        : BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(i, 8));

                    if (clusterMap.TryGetValue(ptrVal, out var matchedCluster))
                    {
                        ulong refVA = sec.address + (ulong)i;

                        // Check the count stored right before this pointer
                        long storedCount = il2Cpp.Is32Bit
                            ? BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(i - 4, 4))
                            : BinaryPrimitives.ReadInt64LittleEndian(bytes.AsSpan(i - 8, 8));

                        if (storedCount > 0 && storedCount < 500000)
                        {
                            bool countMatches = Math.Abs(storedCount - matchedCluster.TotalCount) <= Math.Max(10, matchedCluster.TotalCount * 0.15)
                                || (expectedMethodCount > 0 && Math.Abs(storedCount - expectedMethodCount) <= Math.Max(5, expectedMethodCount * 0.05));

                            if (countMatches)
                            {
                                // Possible field in Il2CppCodeRegistration:
                                // Pre-24.2: methodPointers is field 1 (offset = ptrSize)
                                // >= 24.2: genericMethodPointers is field 3 (offset = 3*ptrSize), invokerPointers is field 5/6
                                ulong[] candidateBaseOffsets = il2Cpp.Version >= 24.2
                                    ? new ulong[] { ptrSize, ptrSize * 3, ptrSize * 4, ptrSize * 5, ptrSize * 6 }
                                    : new ulong[] { ptrSize, ptrSize * 3, ptrSize * 5, ptrSize * 7 };

                                foreach (var baseOffset in candidateBaseOffsets)
                                {
                                    if (refVA >= baseOffset)
                                    {
                                        ulong candVA = refVA - baseOffset;
                                        if (IsInData(candVA, dataSections) && !candidates.ContainsKey(candVA))
                                        {
                                            var score = EvaluateCodeRegistration(il2Cpp, candVA, dataSections, execSections, expectedMethodCount, expectedImageCount, densityThreshold, out var reason);
                                            if (score >= 50)
                                            {
                                                candidates[candVA] = new CandidateRegistration
                                                {
                                                    VA = candVA,
                                                    Score = score + 20, // bonus for cluster head reference
                                                    Reason = "ClusterRef: " + reason
                                                };
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Strategy 2: Direct structural pattern sweep across data sections
            foreach (var sec in dataSections)
            {
                var length = (int)Math.Min((ulong)int.MaxValue, sec.offsetEnd - sec.offset);
                var step = (int)ptrSize;
                int structSizeEstimate = (int)ptrSize * 16;
                if (length < structSizeEstimate) continue;

                il2Cpp.Position = sec.offset;
                var bytes = il2Cpp.ReadBytes(length);

                for (int i = 0; i <= length - structSizeEstimate; i += step)
                {
                    ulong candVA = sec.address + (ulong)i;
                    if (candidates.ContainsKey(candVA)) continue;

                    var score = EvaluateCodeRegistration(il2Cpp, candVA, dataSections, execSections, expectedMethodCount, expectedImageCount, densityThreshold, out var reason);
                    if (score >= 60)
                    {
                        candidates[candVA] = new CandidateRegistration
                        {
                            VA = candVA,
                            Score = score,
                            Reason = "DirectSweep: " + reason
                        };
                    }
                }
            }

            return candidates.Values.OrderByDescending(x => x.Score).ToList();
        }

        public static List<CandidateRegistration> FindMetadataRegistrationCandidates(
            Il2Cpp il2Cpp,
            List<SearchSection> dataSections,
            int expectedTypeDefsCount)
        {
            var candidates = new Dictionary<ulong, CandidateRegistration>();
            var ptrSize = (int)il2Cpp.PointerSize;
            int structSizeEstimate = ptrSize * 16;

            foreach (var sec in dataSections)
            {
                var length = (int)Math.Min((ulong)int.MaxValue, sec.offsetEnd - sec.offset);
                if (length < structSizeEstimate) continue;

                il2Cpp.Position = sec.offset;
                var bytes = il2Cpp.ReadBytes(length);

                for (int i = 0; i <= length - structSizeEstimate; i += ptrSize)
                {
                    ulong candVA = sec.address + (ulong)i;
                    var score = EvaluateMetadataRegistration(il2Cpp, candVA, dataSections, expectedTypeDefsCount, out var reason);
                    if (score >= 60)
                    {
                        candidates[candVA] = new CandidateRegistration
                        {
                            VA = candVA,
                            Score = score,
                            Reason = reason
                        };
                    }
                }
            }

            return candidates.Values.OrderByDescending(x => x.Score).ToList();
        }

        public static double EvaluateCodeRegistration(
            Il2Cpp il2Cpp,
            ulong candVA,
            List<SearchSection> dataSections,
            List<SearchSection> execSections,
            int expectedMethodCount,
            int expectedImageCount,
            double densityThreshold,
            out string reason)
        {
            reason = "";
            double score = 0;
            var words = ReadWords(il2Cpp, candVA, 18);
            if (words == null || words.Length < 14) return 0;

            // Check Unity >= 24.2 (Modern CodeGenModules layout)
            if (il2Cpp.Version >= 24.2)
            {
                // In modern Unity, invokerPointers is typically at word 4 or 5
                int[] invokerIndices = new[] { 4, 5, 6 };

                foreach (var invIdx in invokerIndices)
                {
                    long invCount = (long)words[invIdx];
                    ulong invPtr = words[invIdx + 1];

                    if (invCount >= 10 && invCount < 200000 && IsInData(invPtr, dataSections))
                    {
                        double density = CalculateCodeDensity(il2Cpp, invPtr, (int)Math.Min(invCount, 24), execSections, out _);
                        if (density >= densityThreshold)
                        {
                            score += 45;
                            reason += $"invokers(idx={invIdx},cnt={invCount},d={density:P0}) ";
                            break;
                        }
                    }
                }

                // Check genericMethodPointers (word 2/3)
                long genCount = (long)words[2];
                ulong genPtr = words[3];
                if (genCount >= 0 && genCount < 200000)
                {
                    if (genCount == 0 && genPtr == 0)
                    {
                        score += 15;
                    }
                    else if (genCount > 0 && IsInData(genPtr, dataSections))
                    {
                        double density = CalculateCodeDensity(il2Cpp, genPtr, (int)Math.Min(genCount, 20), execSections, out _);
                        if (density >= densityThreshold)
                        {
                            score += 35;
                            reason += $"genericMethods(cnt={genCount},d={density:P0}) ";
                        }
                    }
                }

                // Check codeGenModulesCount and codeGenModules (words 12-16)
                for (int mIdx = 10; mIdx <= Math.Min(16, words.Length - 2); mIdx++)
                {
                    long modCount = (long)words[mIdx];
                    ulong modPtr = words[mIdx + 1];

                    if (modCount >= 1 && modCount <= 2000 && IsInData(modPtr, dataSections))
                    {
                        // Check if expectedImageCount matches
                        bool imageCountBonus = expectedImageCount > 0 && modCount == expectedImageCount;

                        // Check first module pointer
                        var modulePointers = ReadWords(il2Cpp, modPtr, 1);
                        if (modulePointers != null && modulePointers.Length > 0 && IsInData(modulePointers[0], dataSections))
                        {
                            ulong firstModVA = modulePointers[0];
                            var modWords = ReadWords(il2Cpp, firstModVA, 3);
                            if (modWords != null && modWords.Length >= 3)
                            {
                                string modName = ReadAsciiString(il2Cpp, modWords[0], 64);
                                if (!string.IsNullOrEmpty(modName) && (modName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) || modName.Length >= 3))
                                {
                                    score += 50;
                                    if (imageCountBonus) score += 25;
                                    reason += $"codeGenModules(cnt={modCount},name={modName}) ";
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            else
            {
                // Unity < 24.2 (Legacy layout)
                // word 0: methodPointersCount, word 1: methodPointers
                long methodCount = (long)words[0];
                ulong methodPtr = words[1];

                if (methodCount >= 10 && methodCount < 500000 && IsInData(methodPtr, dataSections))
                {
                    double density = CalculateCodeDensity(il2Cpp, methodPtr, (int)Math.Min(methodCount, 32), execSections, out _);
                    if (density >= densityThreshold)
                    {
                        score += 60;
                        if (expectedMethodCount > 0 && Math.Abs(methodCount - expectedMethodCount) <= Math.Max(5, expectedMethodCount * 0.05))
                        {
                            score += 40;
                        }
                        reason += $"methodPointers(cnt={methodCount},d={density:P0}) ";
                    }
                }

                // Check genericMethodPointers and invokerPointers
                for (int w = 2; w <= words.Length - 2; w += 2)
                {
                    long cnt = (long)words[w];
                    ulong ptr = words[w + 1];
                    if (cnt >= 10 && cnt < 200000 && IsInData(ptr, dataSections))
                    {
                        double density = CalculateCodeDensity(il2Cpp, ptr, (int)Math.Min(cnt, 20), execSections, out _);
                        if (density >= densityThreshold)
                        {
                            score += 25;
                            reason += $"ptrCluster(w={w},cnt={cnt},d={density:P0}) ";
                        }
                    }
                }
            }

            return score;
        }

        public static double EvaluateMetadataRegistration(
            Il2Cpp il2Cpp,
            ulong candVA,
            List<SearchSection> dataSections,
            int expectedTypeDefsCount,
            out string reason)
        {
            reason = "";
            double score = 0;
            var words = ReadWords(il2Cpp, candVA, 16);
            if (words == null || words.Length < 14) return 0;

            // Fields:
            // 0: genericClassesCount, 1: genericClasses
            // 2: genericInstsCount, 3: genericInsts
            // 4: genericMethodTableCount, 5: genericMethodTable
            // 6: typesCount, 7: types
            // 8: methodSpecsCount, 9: methodSpecs
            // 10: fieldOffsetsCount, 11: fieldOffsets
            // 12: typeDefinitionsSizesCount, 13: typeDefinitionsSizes

            // Check that all counts are within valid range [0, 500000)
            for (int i = 0; i <= 12; i += 2)
            {
                long cnt = (long)words[i];
                if (cnt < 0 || cnt >= 500000) return 0;
            }

            // 1. Validate types (field 6, 7)
            long typesCount = (long)words[6];
            ulong typesPtr = words[7];
            if (typesCount > 0 && IsInData(typesPtr, dataSections))
            {
                score += 35;
                if (expectedTypeDefsCount > 0 && typesCount >= expectedTypeDefsCount)
                {
                    score += 15;
                }
                reason += $"types(cnt={typesCount}) ";
            }
            else
            {
                return 0; // types is strictly required
            }

            // 2. Validate fieldOffsets (field 10, 11)
            long fieldOffsetsCount = (long)words[10];
            ulong fieldOffsetsPtr = words[11];
            if (fieldOffsetsCount > 0 && IsInData(fieldOffsetsPtr, dataSections))
            {
                score += 35;
                if (expectedTypeDefsCount > 0 && Math.Abs(fieldOffsetsCount - expectedTypeDefsCount) <= Math.Max(5, expectedTypeDefsCount * 0.10))
                {
                    score += 30;
                }
                reason += $"fieldOffsets(cnt={fieldOffsetsCount}) ";
            }
            else
            {
                return 0; // fieldOffsets is strictly required
            }

            // 3. Validate typeDefinitionsSizes (field 12, 13)
            long typeSizesCount = (long)words[12];
            ulong typeSizesPtr = words[13];
            if (typeSizesCount > 0 && IsInData(typeSizesPtr, dataSections))
            {
                score += 35;
                if (expectedTypeDefsCount > 0 && Math.Abs(typeSizesCount - expectedTypeDefsCount) <= Math.Max(5, expectedTypeDefsCount * 0.10))
                {
                    score += 30;
                }
                reason += $"typeSizes(cnt={typeSizesCount}) ";
            }

            // 4. Validate other optional pointer fields
            if (words[1] == 0 || IsInData(words[1], dataSections)) score += 5; // genericClasses
            if (words[3] == 0 || IsInData(words[3], dataSections)) score += 5; // genericInsts
            if (words[5] == 0 || IsInData(words[5], dataSections)) score += 5; // genericMethodTable
            if (words[9] == 0 || IsInData(words[9], dataSections)) score += 5; // methodSpecs

            return score;
        }

        private static List<RegistrationPair> BuildAndRankPairs(
            Il2Cpp il2Cpp,
            List<CandidateRegistration> codeCandidates,
            List<CandidateRegistration> metaCandidates,
            List<SearchSection> dataSections,
            List<SearchSection> execSections,
            int expectedTypeDefsCount)
        {
            var pairs = new List<RegistrationPair>();

            // Proximity pairing: CodeRegistration and MetadataRegistration are almost always placed
            // in the same translation unit within 0x20000 bytes of each other!
            foreach (var code in codeCandidates)
            {
                // Local proximity sweep around this code candidate if no meta candidates are nearby
                var nearbyMeta = metaCandidates.Where(m => Math.Abs((long)m.VA - (long)code.VA) <= 0x40000).ToList();
                if (nearbyMeta.Count == 0)
                {
                    // Search in window [code.VA - 0x20000, code.VA + 0x20000]
                    ulong start = code.VA > 0x20000 ? code.VA - 0x20000 : 0;
                    ulong end = code.VA + 0x20000;
                    var localSec = dataSections.FirstOrDefault(s => code.VA >= s.address && code.VA < s.addressEnd);
                    if (localSec != null)
                    {
                        start = Math.Max(start, localSec.address);
                        end = Math.Min(end, localSec.addressEnd);
                        for (ulong v = start; v + il2Cpp.PointerSize * 16 <= end; v += il2Cpp.PointerSize)
                        {
                            var score = EvaluateMetadataRegistration(il2Cpp, v, dataSections, expectedTypeDefsCount, out var reason);
                            if (score >= 50)
                            {
                                nearbyMeta.Add(new CandidateRegistration { VA = v, Score = score, Reason = "LocalProximity: " + reason });
                            }
                        }
                    }
                }

                foreach (var meta in nearbyMeta.Concat(metaCandidates.Take(10)))
                {
                    long dist = Math.Abs((long)code.VA - (long)meta.VA);
                    double proxBonus = 0;
                    if (dist < 0x2000) proxBonus = 70;
                    else if (dist < 0x10000) proxBonus = 50;
                    else if (dist < 0x40000) proxBonus = 30;
                    else proxBonus = -30; // penalize distant pairs

                    pairs.Add(new RegistrationPair
                    {
                        CodeRegVA = code.VA,
                        MetaRegVA = meta.VA,
                        CodeScore = code.Score,
                        MetaScore = meta.Score,
                        ProximityScore = proxBonus,
                        Details = $"Code: {code.Reason} | Meta: {meta.Reason} | Dist: 0x{dist:X}"
                    });
                }
            }

            return pairs.OrderByDescending(p => p.TotalScore).ToList();
        }

        private static bool IsInExec(ulong va, List<SearchSection> execSections)
        {
            ulong alignedVa = va & ~1UL; // Thumb/ARM mask
            for (int i = 0; i < execSections.Count; i++)
            {
                var s = execSections[i];
                if (alignedVa >= s.address && alignedVa < s.addressEnd)
                    return true;
            }
            return false;
        }

        private static bool IsInData(ulong va, List<SearchSection> dataSections)
        {
            for (int i = 0; i < dataSections.Count; i++)
            {
                var s = dataSections[i];
                if (va >= s.address && va < s.addressEnd)
                    return true;
            }
            return false;
        }

        private static ulong[] ReadWords(Il2Cpp il2Cpp, ulong va, int count)
        {
            try
            {
                if (!il2Cpp.TryMapVATR(va, out var offset) || offset + (ulong)(count * (int)il2Cpp.PointerSize) > (ulong)il2Cpp.Length)
                    return null;

                il2Cpp.Position = offset;
                var result = new ulong[count];
                for (int i = 0; i < count; i++)
                {
                    result[i] = il2Cpp.ReadUIntPtr();
                }
                return result;
            }
            catch
            {
                return null;
            }
        }

        private static double CalculateCodeDensity(Il2Cpp il2Cpp, ulong tableVA, int sampleCount, List<SearchSection> execSections, out int validCodeCount)
        {
            validCodeCount = 0;
            if (sampleCount <= 0) return 0;

            var words = ReadWords(il2Cpp, tableVA, sampleCount);
            if (words == null || words.Length == 0) return 0;

            for (int i = 0; i < words.Length; i++)
            {
                if (IsInExec(words[i], execSections))
                    validCodeCount++;
            }
            return (double)validCodeCount / words.Length;
        }

        private static string ReadAsciiString(Il2Cpp il2Cpp, ulong va, int maxLen = 64)
        {
            try
            {
                if (!il2Cpp.TryMapVATR(va, out var offset) || offset >= (ulong)il2Cpp.Length)
                    return null;

                il2Cpp.Position = offset;
                var bytes = new List<byte>();
                for (int i = 0; i < maxLen; i++)
                {
                    if (il2Cpp.Position >= (ulong)il2Cpp.Length) break;
                    byte b = il2Cpp.ReadByte();
                    if (b == 0) break;
                    if (b < 0x20 || b > 0x7E) return null; // non-printable
                    bytes.Add(b);
                }
                return bytes.Count >= 3 ? Encoding.ASCII.GetString(bytes.ToArray()) : null;
            }
            catch
            {
                return null;
            }
        }
    }
}
