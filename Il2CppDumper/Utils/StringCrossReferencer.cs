using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Il2CppDumper
{
    public enum StringTargetType
    {
        Registration,
        Assertion,
        ModuleName
    }

    public class StringTargetInfo
    {
        public string Text { get; set; }
        public StringTargetType Type { get; set; }
        public double BaseWeight { get; set; }
    }

    public class StringMatch
    {
        public StringTargetInfo Target { get; set; }
        public ulong VA { get; set; }
        public ulong FileOffset { get; set; }
    }

    public static class StringCrossReferencer
    {
        // Corpus of runtime registration, assertion, and core assembly strings
        public static readonly List<StringTargetInfo> TargetCorpus = new()
        {
            // Registration & API strings
            new StringTargetInfo { Text = "il2cpp_codegen_register", Type = StringTargetType.Registration, BaseWeight = 100 },
            new StringTargetInfo { Text = "MetadataCache::Register", Type = StringTargetType.Registration, BaseWeight = 95 },
            new StringTargetInfo { Text = "MetadataCache::Initialize", Type = StringTargetType.Registration, BaseWeight = 90 },
            new StringTargetInfo { Text = "il2cpp::vm::MetadataCache::Register", Type = StringTargetType.Registration, BaseWeight = 95 },
            new StringTargetInfo { Text = "il2cpp::vm::MetadataCache::Initialize", Type = StringTargetType.Registration, BaseWeight = 90 },
            
            // Assertion & Diagnostic strings
            new StringTargetInfo { Text = "Failed to initialize il2cpp metadata", Type = StringTargetType.Assertion, BaseWeight = 85 },
            new StringTargetInfo { Text = "Metadata version %d does not match expected %d", Type = StringTargetType.Assertion, BaseWeight = 80 },
            new StringTargetInfo { Text = "Could not find the requested dynamic method", Type = StringTargetType.Assertion, BaseWeight = 75 },
            new StringTargetInfo { Text = "NullReferenceException", Type = StringTargetType.Assertion, BaseWeight = 60 },
            
            // Core Assembly Module Names
            new StringTargetInfo { Text = "mscorlib.dll", Type = StringTargetType.ModuleName, BaseWeight = 90 },
            new StringTargetInfo { Text = "System.dll", Type = StringTargetType.ModuleName, BaseWeight = 80 },
            new StringTargetInfo { Text = "UnityEngine.CoreModule.dll", Type = StringTargetType.ModuleName, BaseWeight = 85 },
            new StringTargetInfo { Text = "UnityEngine.dll", Type = StringTargetType.ModuleName, BaseWeight = 80 },
            new StringTargetInfo { Text = "Assembly-CSharp.dll", Type = StringTargetType.ModuleName, BaseWeight = 75 }
        };

        public static bool Search(Il2Cpp il2Cpp, Metadata metadata, double densityThreshold = 0.80)
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

            // 1. Locate string occurrences in binary memory
            var matches = FindStringMatches(il2Cpp, dataSections, execSections);
            if (matches.Count == 0)
            {
                return false;
            }

            Console.WriteLine($"[+] StringCrossReferencer: Found {matches.Count} target string occurrences");

            // 2. Discover candidates via XREFs (ARM64, x86_64, and Data-Pointer Multi-Hop)
            var codeCandidates = new Dictionary<ulong, CandidateRegistration>();
            var metaCandidates = new Dictionary<ulong, CandidateRegistration>();

            // Strategy A: Module Name Multi-Hop Resolver (for mscorlib.dll, UnityEngine.dll, etc.)
            foreach (var match in matches.Where(m => m.Target.Type == StringTargetType.ModuleName))
            {
                TraceModuleXrefs(il2Cpp, match, dataSections, execSections, expectedImageCount: imageCount, codeCandidates, metaCandidates);
            }

            // Strategy B: Code Instruction XREFs (ARM64 & x86_64) for Registration & Assertion Strings
            foreach (var match in matches.Where(m => m.Target.Type != StringTargetType.ModuleName))
            {
                TraceCodeXrefs(il2Cpp, match, dataSections, execSections, typeDefsCount, densityThreshold, codeCandidates, metaCandidates);
            }

            // 3. Pair and rank candidate registrations
            var pairs = RankCandidates(il2Cpp, codeCandidates.Values.ToList(), metaCandidates.Values.ToList(), dataSections, typeDefsCount);
            if (pairs.Count == 0)
            {
                return false;
            }

            // 4. Try candidate pairs with AutoPlusInit
            var savedVersion = il2Cpp.Version;
            foreach (var pair in pairs)
            {
                try
                {
                    il2Cpp.Version = savedVersion;
                    if (il2Cpp.AutoPlusInit(pair.CodeRegVA, pair.MetaRegVA))
                    {
                        Console.WriteLine($"[+] StringCrossReferencer resolved registration pair (Score: {pair.TotalScore:F0}):");
                        Console.WriteLine($"    CodeRegistration    : 0x{pair.CodeRegVA:X}");
                        Console.WriteLine($"    MetadataRegistration: 0x{pair.MetaRegVA:X}");
                        if (!string.IsNullOrEmpty(pair.Details))
                        {
                            Console.WriteLine($"    Source: {pair.Details}");
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

        public static List<StringMatch> FindStringMatches(Il2Cpp il2Cpp, List<SearchSection> dataSections, List<SearchSection> execSections)
        {
            var matches = new List<StringMatch>();
            var allSections = dataSections.Concat(execSections).ToList();

            foreach (var sec in allSections)
            {
                var length = (int)Math.Min((ulong)int.MaxValue, sec.offsetEnd - sec.offset);
                if (length < 8) continue;

                il2Cpp.Position = sec.offset;
                var bytes = il2Cpp.ReadBytes(length);

                foreach (var target in TargetCorpus)
                {
                    byte[] targetBytes = Encoding.ASCII.GetBytes(target.Text + "\0");
                    int idx = 0;
                    while ((idx = IndexOfSequence(bytes, targetBytes, idx)) >= 0)
                    {
                        matches.Add(new StringMatch
                        {
                            Target = target,
                            VA = sec.address + (ulong)idx,
                            FileOffset = sec.offset + (ulong)idx
                        });
                        idx += targetBytes.Length;
                    }

                    // Also check without null terminator if not found with null
                    if (matches.All(m => m.Target.Text != target.Text))
                    {
                        byte[] noNull = Encoding.ASCII.GetBytes(target.Text);
                        int idx2 = 0;
                        while ((idx2 = IndexOfSequence(bytes, noNull, idx2)) >= 0)
                        {
                            matches.Add(new StringMatch
                            {
                                Target = target,
                                VA = sec.address + (ulong)idx2,
                                FileOffset = sec.offset + (ulong)idx2
                            });
                            idx2 += noNull.Length;
                        }
                    }
                }
            }

            return matches;
        }

        private static void TraceModuleXrefs(
            Il2Cpp il2Cpp,
            StringMatch match,
            List<SearchSection> dataSections,
            List<SearchSection> execSections,
            int expectedImageCount,
            Dictionary<ulong, CandidateRegistration> codeCandidates,
            Dictionary<ulong, CandidateRegistration> metaCandidates)
        {
            var ptrSize = il2Cpp.PointerSize;

            // Hop 1: Find direct pointer to module string in Data sections (moduleName in Il2CppCodeGenModule)
            var modulePointers = FindDirectDataPointers(il2Cpp, match.VA, dataSections);
            foreach (var modStructVA in modulePointers)
            {
                // Validate if modStructVA is an Il2CppCodeGenModule:
                // [0] moduleName (points to string)
                // [1] methodPointerCount (long >= 0)
                // [2] methodPointers (points to code pointer cluster or 0)
                var words = ReadWords(il2Cpp, modStructVA, 4);
                if (words == null || words.Length < 3) continue;

                long methodCount = (long)words[1];
                ulong methodPtrs = words[2];

                if (methodCount >= 0 && methodCount < 100000)
                {
                    // Hop 2: Find references to modStructVA (elements of codeGenModules[] array)
                    var arrayElemPointers = FindDirectDataPointers(il2Cpp, modStructVA, dataSections);
                    foreach (var elemVA in arrayElemPointers)
                    {
                        // Hop 3: Search for pointers referencing codeGenModules[] array
                        // The element could be index 0..50 in the array
                        int maxBacktrack = expectedImageCount > 0 ? Math.Min(expectedImageCount, 64) : 32;
                        for (int k = 0; k < maxBacktrack; k++)
                        {
                            ulong candidateArrayStart = elemVA - (ulong)k * ptrSize;
                            var codeGenModuleRefPointers = FindDirectDataPointers(il2Cpp, candidateArrayStart, dataSections);

                            foreach (var codeGenPtrAddr in codeGenModuleRefPointers)
                            {
                                // In Il2CppCodeRegistration, right before codeGenModules is codeGenModulesCount
                                if (codeGenPtrAddr >= ptrSize)
                                {
                                    ulong countAddr = codeGenPtrAddr - ptrSize;
                                    var countWords = ReadWords(il2Cpp, countAddr, 1);
                                    if (countWords != null && countWords.Length > 0)
                                    {
                                        long modCount = (long)countWords[0];
                                        if (modCount >= 1 && modCount <= 2000)
                                        {
                                            // Candidate CodeRegistration!
                                            // Depending on Unity version, codeGenModules is at offset:
                                            // v24.2 - v24.4: offset 13 * ptrSize
                                            // v24.5 - v27.0: offset 14 * ptrSize
                                            // v27.1 - v31.0: offset 14..15 * ptrSize
                                            // v35+: offset 16 * ptrSize
                                            ulong[] possibleOffsets = new ulong[] { ptrSize * 13, ptrSize * 14, ptrSize * 15, ptrSize * 16 };
                                            foreach (var off in possibleOffsets)
                                            {
                                                if (codeGenPtrAddr >= off)
                                                {
                                                    ulong candCodeReg = codeGenPtrAddr - off;
                                                    if (!codeCandidates.ContainsKey(candCodeReg))
                                                    {
                                                        double score = PointerDensityScanner.EvaluateCodeRegistration(
                                                            il2Cpp, candCodeReg, dataSections, execSections, 0, (int)modCount, 0.80, out var reason);
                                                        if (score >= 60)
                                                        {
                                                            codeCandidates[candCodeReg] = new CandidateRegistration
                                                            {
                                                                VA = candCodeReg,
                                                                Score = score + 30, // string XREF bonus
                                                                Reason = $"ModuleXREF({match.Target.Text}): " + reason
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
                    }
                }
            }
        }

        private static void TraceCodeXrefs(
            Il2Cpp il2Cpp,
            StringMatch match,
            List<SearchSection> dataSections,
            List<SearchSection> execSections,
            int expectedTypeDefsCount,
            double densityThreshold,
            Dictionary<ulong, CandidateRegistration> codeCandidates,
            Dictionary<ulong, CandidateRegistration> metaCandidates)
        {
            var ptrSize = il2Cpp.PointerSize;

            // 1. ARM64 Instruction Disassembly XREFs
            if (ptrSize == 8 && (il2Cpp is Elf64 || il2Cpp is Macho64 || il2Cpp is NSO))
            {
                TraceArm64Xrefs(il2Cpp, match, dataSections, execSections, expectedTypeDefsCount, densityThreshold, codeCandidates, metaCandidates);
            }

            // 2. x86_64 RIP-relative LEA XREFs
            if (ptrSize == 8 && (il2Cpp is PE || il2Cpp is Elf64 || il2Cpp is Macho64))
            {
                TraceX64Xrefs(il2Cpp, match, dataSections, execSections, expectedTypeDefsCount, densityThreshold, codeCandidates, metaCandidates);
            }

            // 3. Direct Pointer XREFs in Data sections (tables, registration records)
            var directPointers = FindDirectDataPointers(il2Cpp, match.VA, dataSections);
            foreach (var ptrAddr in directPointers)
            {
                // Inspect neighboring words in data for candidate registrations
                ulong windowStart = ptrAddr >= ptrSize * 16 ? ptrAddr - ptrSize * 16 : 0;
                ulong windowEnd = ptrAddr + ptrSize * 16;
                for (ulong v = windowStart; v <= windowEnd; v += ptrSize)
                {
                    if (!codeCandidates.ContainsKey(v))
                    {
                        double score = PointerDensityScanner.EvaluateCodeRegistration(il2Cpp, v, dataSections, execSections, 0, 0, densityThreshold, out var reason);
                        if (score >= 60)
                        {
                            codeCandidates[v] = new CandidateRegistration
                            {
                                VA = v,
                                Score = score + 25,
                                Reason = $"DataXREF({match.Target.Text}): " + reason
                            };
                        }
                    }

                    if (!metaCandidates.ContainsKey(v))
                    {
                        double score = PointerDensityScanner.EvaluateMetadataRegistration(il2Cpp, v, dataSections, expectedTypeDefsCount, out var reason);
                        if (score >= 60)
                        {
                            metaCandidates[v] = new CandidateRegistration
                            {
                                VA = v,
                                Score = score + 25,
                                Reason = $"DataXREF({match.Target.Text}): " + reason
                            };
                        }
                    }
                }
            }
        }

        private static void TraceArm64Xrefs(
            Il2Cpp il2Cpp,
            StringMatch match,
            List<SearchSection> dataSections,
            List<SearchSection> execSections,
            int expectedTypeDefsCount,
            double densityThreshold,
            Dictionary<ulong, CandidateRegistration> codeCandidates,
            Dictionary<ulong, CandidateRegistration> metaCandidates)
        {
            foreach (var sec in execSections)
            {
                var length = (int)Math.Min((ulong)int.MaxValue, sec.offsetEnd - sec.offset);
                if (length < 16) continue;

                il2Cpp.Position = sec.offset;
                var bytes = il2Cpp.ReadBytes(length);
                int insnCount = length / 4;

                ulong?[] regValues = new ulong?[32];
                int[] regSetAt = new int[32];
                for (int r = 0; r < 32; r++) regSetAt[r] = -100;

                for (int i = 0; i < insnCount; i++)
                {
                    uint insn = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(i * 4, 4));
                    ulong pc = sec.address + (ulong)(i * 4);

                    if (Arm64RegisterScanner.DecodeAdrp(insn, pc, out int adrpRd, out ulong targetPage))
                    {
                        regValues[adrpRd] = targetPage;
                        regSetAt[adrpRd] = i;
                        continue;
                    }

                    if (Arm64RegisterScanner.DecodeAddImm64(insn, out int addRd, out int addRn, out ulong addImm))
                    {
                        if (regValues[addRn].HasValue && i - regSetAt[addRn] <= 16)
                        {
                            ulong resolvedVA = regValues[addRn].Value + addImm;
                            regValues[addRd] = resolvedVA;
                            regSetAt[addRd] = i;

                            // Did this instruction load our target string?
                            if (resolvedVA == match.VA)
                            {
                                // XREF confirmed! Now inspect the surrounding function window [i - 48, i + 48]
                                ScanArm64FunctionWindow(il2Cpp, bytes, i, sec.address, dataSections, execSections, expectedTypeDefsCount, densityThreshold, match.Target.Text, codeCandidates, metaCandidates);
                            }
                        }
                        else
                        {
                            regValues[addRd] = null;
                        }
                        continue;
                    }

                    if (Arm64RegisterScanner.IsBranchLink(insn))
                    {
                        // Reset volatile parameter registers
                        regValues[0] = null;
                        regValues[1] = null;
                        regValues[2] = null;
                        regValues[3] = null;
                    }
                }
            }
        }

        private static void ScanArm64FunctionWindow(
            Il2Cpp il2Cpp,
            byte[] bytes,
            int targetInsnIdx,
            ulong secBaseVA,
            List<SearchSection> dataSections,
            List<SearchSection> execSections,
            int expectedTypeDefsCount,
            double densityThreshold,
            string stringName,
            Dictionary<ulong, CandidateRegistration> codeCandidates,
            Dictionary<ulong, CandidateRegistration> metaCandidates)
        {
            int startIdx = Math.Max(0, targetInsnIdx - 48);
            int endIdx = Math.Min(bytes.Length / 4, targetInsnIdx + 48);

            ulong?[] regValues = new ulong?[32];
            int[] regSetAt = new int[32];
            for (int r = 0; r < 32; r++) regSetAt[r] = -100;

            for (int i = startIdx; i < endIdx; i++)
            {
                uint insn = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(i * 4, 4));
                ulong pc = secBaseVA + (ulong)(i * 4);

                if (Arm64RegisterScanner.DecodeAdrp(insn, pc, out int adrpRd, out ulong targetPage))
                {
                    regValues[adrpRd] = targetPage;
                    regSetAt[adrpRd] = i;
                    continue;
                }

                if (Arm64RegisterScanner.DecodeAddImm64(insn, out int addRd, out int addRn, out ulong addImm))
                {
                    if (regValues[addRn].HasValue && i - regSetAt[addRn] <= 16)
                    {
                        ulong resolvedVA = regValues[addRn].Value + addImm;
                        regValues[addRd] = resolvedVA;
                        regSetAt[addRd] = i;

                        // If resolved address is in Data, evaluate it!
                        if (IsInData(resolvedVA, dataSections))
                        {
                            EvaluateAndAddCandidate(il2Cpp, resolvedVA, dataSections, execSections, expectedTypeDefsCount, densityThreshold, $"Arm64XREF({stringName})", codeCandidates, metaCandidates);
                        }
                    }
                    continue;
                }

                if (Arm64RegisterScanner.IsBranchLink(insn))
                {
                    // Check X0 & X1 argument pair
                    if (regValues[0].HasValue && regValues[1].HasValue &&
                        i - regSetAt[0] <= 16 && i - regSetAt[1] <= 16)
                    {
                        ulong cand0 = regValues[0].Value;
                        ulong cand1 = regValues[1].Value;

                        if (IsInData(cand0, dataSections) && IsInData(cand1, dataSections))
                        {
                            EvaluateAndAddCandidate(il2Cpp, cand0, dataSections, execSections, expectedTypeDefsCount, densityThreshold, $"Arm64CallXREF({stringName})", codeCandidates, metaCandidates);
                            EvaluateAndAddCandidate(il2Cpp, cand1, dataSections, execSections, expectedTypeDefsCount, densityThreshold, $"Arm64CallXREF({stringName})", codeCandidates, metaCandidates);
                        }
                    }
                }
            }
        }

        private static void TraceX64Xrefs(
            Il2Cpp il2Cpp,
            StringMatch match,
            List<SearchSection> dataSections,
            List<SearchSection> execSections,
            int expectedTypeDefsCount,
            double densityThreshold,
            Dictionary<ulong, CandidateRegistration> codeCandidates,
            Dictionary<ulong, CandidateRegistration> metaCandidates)
        {
            foreach (var sec in execSections)
            {
                var length = (int)Math.Min((ulong)int.MaxValue, sec.offsetEnd - sec.offset);
                if (length < 16) continue;

                il2Cpp.Position = sec.offset;
                var bytes = il2Cpp.ReadBytes(length);

                for (int i = 0; i <= length - 7; i++)
                {
                    ulong pc = sec.address + (ulong)i;
                    if (DecodeX64RipLea(bytes.AsSpan(i, 7), pc, out _, out ulong targetVA))
                    {
                        if (targetVA == match.VA)
                        {
                            // Found x86_64 reference to string!
                            // Scan window [i - 128, i + 128] for other RIP-relative LEAs loading Data
                            int startIdx = Math.Max(0, i - 128);
                            int endIdx = Math.Min(length - 7, i + 128);

                            for (int j = startIdx; j <= endIdx; j++)
                            {
                                ulong subPC = sec.address + (ulong)j;
                                if (DecodeX64RipLea(bytes.AsSpan(j, 7), subPC, out _, out ulong subTargetVA))
                                {
                                    if (IsInData(subTargetVA, dataSections))
                                    {
                                        EvaluateAndAddCandidate(il2Cpp, subTargetVA, dataSections, execSections, expectedTypeDefsCount, densityThreshold, $"x64XREF({match.Target.Text})", codeCandidates, metaCandidates);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        public static bool DecodeX64RipLea(ReadOnlySpan<byte> span, ulong pc, out int reg, out ulong targetVA)
        {
            reg = 0;
            targetVA = 0;
            if (span.Length < 7) return false;

            // REX.W prefix (0x48 .. 0x4F) + 0x8D (LEA) + ModR/M [disp32]
            if (span[0] >= 0x48 && span[0] <= 0x4F && span[1] == 0x8D && (span[2] & 0xC7) == 0x05)
            {
                reg = ((span[0] & 0x04) << 1) | ((span[2] >> 3) & 0x07);
                int disp32 = BinaryPrimitives.ReadInt32LittleEndian(span.Slice(3, 4));
                targetVA = (ulong)((long)pc + 7 + disp32);
                return true;
            }

            return false;
        }

        private static void EvaluateAndAddCandidate(
            Il2Cpp il2Cpp,
            ulong candVA,
            List<SearchSection> dataSections,
            List<SearchSection> execSections,
            int expectedTypeDefsCount,
            double densityThreshold,
            string source,
            Dictionary<ulong, CandidateRegistration> codeCandidates,
            Dictionary<ulong, CandidateRegistration> metaCandidates)
        {
            if (!codeCandidates.ContainsKey(candVA))
            {
                double score = PointerDensityScanner.EvaluateCodeRegistration(il2Cpp, candVA, dataSections, execSections, 0, 0, densityThreshold, out var reason);
                if (score >= 55)
                {
                    codeCandidates[candVA] = new CandidateRegistration
                    {
                        VA = candVA,
                        Score = score + 30, // string XREF correlation bonus
                        Reason = $"{source}: {reason}"
                    };
                }
            }

            if (!metaCandidates.ContainsKey(candVA))
            {
                double score = PointerDensityScanner.EvaluateMetadataRegistration(il2Cpp, candVA, dataSections, expectedTypeDefsCount, out var reason);
                if (score >= 55)
                {
                    metaCandidates[candVA] = new CandidateRegistration
                    {
                        VA = candVA,
                        Score = score + 30,
                        Reason = $"{source}: {reason}"
                    };
                }
            }
        }

        private static List<RegistrationPair> RankCandidates(
            Il2Cpp il2Cpp,
            List<CandidateRegistration> codeCandidates,
            List<CandidateRegistration> metaCandidates,
            List<SearchSection> dataSections,
            int expectedTypeDefsCount)
        {
            var pairs = new List<RegistrationPair>();
            var ptrSize = il2Cpp.PointerSize;

            foreach (var code in codeCandidates)
            {
                // Find nearby metadata candidates
                var nearbyMeta = metaCandidates.Where(m => Math.Abs((long)m.VA - (long)code.VA) <= 0x40000).ToList();

                // If none nearby, do a local proximity scan around code.VA
                if (nearbyMeta.Count == 0)
                {
                    ulong start = code.VA > 0x20000 ? code.VA - 0x20000 : 0;
                    ulong end = code.VA + 0x20000;
                    var localSec = dataSections.FirstOrDefault(s => code.VA >= s.address && code.VA < s.addressEnd);
                    if (localSec != null)
                    {
                        start = Math.Max(start, localSec.address);
                        end = Math.Min(end, localSec.addressEnd);
                        for (ulong v = start; v + ptrSize * 16 <= end; v += ptrSize)
                        {
                            var score = PointerDensityScanner.EvaluateMetadataRegistration(il2Cpp, v, dataSections, expectedTypeDefsCount, out var reason);
                            if (score >= 50)
                            {
                                nearbyMeta.Add(new CandidateRegistration { VA = v, Score = score, Reason = "ProximitySweep: " + reason });
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
                    else proxBonus = -30;

                    pairs.Add(new RegistrationPair
                    {
                        CodeRegVA = code.VA,
                        MetaRegVA = meta.VA,
                        CodeScore = code.Score,
                        MetaScore = meta.Score,
                        ProximityScore = proxBonus,
                        Details = $"Code({code.Reason}) | Meta({meta.Reason})"
                    });
                }
            }

            return pairs.OrderByDescending(p => p.TotalScore).ToList();
        }

        public static List<ulong> FindDirectDataPointers(Il2Cpp il2Cpp, ulong targetVA, List<SearchSection> dataSections)
        {
            var results = new List<ulong>();
            var ptrSize = (int)il2Cpp.PointerSize;

            foreach (var sec in dataSections)
            {
                var length = (int)Math.Min((ulong)int.MaxValue, sec.offsetEnd - sec.offset);
                if (length < ptrSize) continue;

                il2Cpp.Position = sec.offset;
                var bytes = il2Cpp.ReadBytes(length);

                for (int i = 0; i <= length - ptrSize; i += ptrSize)
                {
                    ulong ptrVal = il2Cpp.Is32Bit
                        ? BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(i, 4))
                        : BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(i, 8));

                    if (ptrVal == targetVA)
                    {
                        results.Add(sec.address + (ulong)i);
                    }
                }
            }

            return results;
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

        private static int IndexOfSequence(byte[] source, byte[] pattern, int startIndex)
        {
            if (pattern.Length == 0 || source.Length - startIndex < pattern.Length)
                return -1;

            for (int i = startIndex; i <= source.Length - pattern.Length; i++)
            {
                if (source[i] == pattern[0])
                {
                    bool match = true;
                    for (int j = 1; j < pattern.Length; j++)
                    {
                        if (source[i + j] != pattern[j])
                        {
                            match = false;
                            break;
                        }
                    }
                    if (match) return i;
                }
            }
            return -1;
        }
    }
}
