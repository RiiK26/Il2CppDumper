using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Il2CppDumper
{
    public static class Arm64RegisterScanner
    {
        /// <summary>
        /// Scans ARM64 executable segments (.text) for the instruction sequence that passes
        /// CodeRegistration and MetadataRegistration to il2cpp_codegen_register / MetadataCache::Register.
        /// </summary>
        public static bool Search(Il2Cpp il2Cpp, out ulong codeRegistration, out ulong metadataRegistration)
        {
            codeRegistration = 0;
            metadataRegistration = 0;

            if (il2Cpp == null || il2Cpp.PointerSize != 8)
                return false;

            // Get executable sections to scan
            var execSections = GetExecutableSections(il2Cpp);
            if (execSections.Count == 0)
                return false;

            foreach (var section in execSections)
            {
                if (ScanSection(il2Cpp, section.offset, section.size, section.vaddr, out codeRegistration, out metadataRegistration))
                {
                    return true;
                }
            }

            return false;
        }

        public static bool Search(Il2Cpp il2Cpp)
        {
            if (Search(il2Cpp, out var codeReg, out var metaReg))
            {
                Console.WriteLine("[Arm64RegisterScanner] Found CodeRegistration & MetadataRegistration via ARM64 opcode disassembly!");
                Console.WriteLine($"[Arm64RegisterScanner] CodeRegistration     : 0x{codeReg:X}");
                Console.WriteLine($"[Arm64RegisterScanner] MetadataRegistration : 0x{metaReg:X}");
                il2Cpp.Init(codeReg, metaReg);
                return true;
            }
            return false;
        }

        private static bool ScanSection(Il2Cpp il2Cpp, ulong offset, ulong size, ulong vaddr, out ulong codeReg, out ulong metaReg)
        {
            codeReg = 0;
            metaReg = 0;

            if (size < 16 || offset + size > il2Cpp.Length)
                return false;

            // Read instruction buffer
            il2Cpp.Position = offset;
            byte[] buffer = il2Cpp.ReadBytes((int)size);

            int instructionCount = buffer.Length / 4;

            // State tracking for registers X0..X7
            ulong?[] regValues = new ulong?[32];
            int[] regSetAt = new int[32];
            for (int r = 0; r < 32; r++) regSetAt[r] = -100;

            for (int i = 0; i < instructionCount; i++)
            {
                int byteOffset = i * 4;
                uint insn = BitConverter.ToUInt32(buffer, byteOffset);
                ulong pc = vaddr + (ulong)byteOffset;

                // 1. ADRP Xd, label
                if (DecodeAdrp(insn, pc, out int adrpRd, out ulong adrpPage))
                {
                    regValues[adrpRd] = adrpPage;
                    regSetAt[adrpRd] = i;
                    continue;
                }

                // 2. ADD Xd, Xn, #imm12
                if (DecodeAddImm64(insn, out int addRd, out int addRn, out ulong addImm))
                {
                    if (regValues[addRn].HasValue && i - regSetAt[addRn] <= 16)
                    {
                        regValues[addRd] = regValues[addRn].Value + addImm;
                        regSetAt[addRd] = i;
                    }
                    else
                    {
                        regValues[addRd] = null;
                    }
                    continue;
                }

                // 3. LDR Xd, [Xn, #imm12]
                if (DecodeLdrImm64(insn, out int ldrRd, out int ldrRn, out ulong ldrImm))
                {
                    if (regValues[ldrRn].HasValue && i - regSetAt[ldrRn] <= 16)
                    {
                        ulong ptrAddr = regValues[ldrRn].Value + ldrImm;
                        try
                        {
                            ulong targetOffset = il2Cpp.MapVATR(ptrAddr);
                            if (targetOffset > 0 && targetOffset + 8 <= il2Cpp.Length)
                            {
                                il2Cpp.Position = targetOffset;
                                regValues[ldrRd] = il2Cpp.ReadUInt64();
                                regSetAt[ldrRd] = i;
                            }
                            else
                            {
                                regValues[ldrRd] = null;
                            }
                        }
                        catch
                        {
                            regValues[ldrRd] = null;
                        }
                    }
                    else
                    {
                        regValues[ldrRd] = null;
                    }
                    continue;
                }

                // 4. Branch with Link (BL or BLR)
                if (IsBranchLink(insn))
                {
                    // Check if both X0 and X1 were populated within the last 20 instructions
                    if (regValues[0].HasValue && regValues[1].HasValue &&
                        i - regSetAt[0] <= 20 && i - regSetAt[1] <= 20)
                    {
                        ulong cand0 = regValues[0].Value;
                        ulong cand1 = regValues[1].Value;

                        // Check candidate pair: (cand0 = CodeReg, cand1 = MetaReg)
                        if (IsValidRegistrationPair(il2Cpp, cand0, cand1))
                        {
                            codeReg = cand0;
                            metaReg = cand1;
                            return true;
                        }

                        // Check candidate pair: (cand1 = CodeReg, cand0 = MetaReg)
                        if (IsValidRegistrationPair(il2Cpp, cand1, cand0))
                        {
                            codeReg = cand1;
                            metaReg = cand0;
                            return true;
                        }
                    }

                    // Reset volatile parameter registers after call
                    regValues[0] = null;
                    regValues[1] = null;
                    regValues[2] = null;
                    regValues[3] = null;
                }
            }

            return false;
        }

        public static bool DecodeAdrp(uint insn, ulong pc, out int rd, out ulong targetPage)
        {
            rd = 0;
            targetPage = 0;

            // ADRP: [31]=1, [30:29]=immlo, [28:24]=10000, [23:5]=immhi, [4:0]=Rd
            if ((insn & 0x9F000000) == 0x90000000)
            {
                rd = (int)(insn & 0x1F);
                uint immlo = (insn >> 29) & 0x3;
                uint immhi = (insn >> 5) & 0x7FFFF;
                long imm = (long)((immhi << 2) | immlo);

                // Sign-extend 21-bit
                if ((imm & (1L << 20)) != 0)
                    imm -= (1L << 21);

                targetPage = (pc & ~0xFFFUL) + (ulong)(imm << 12);
                return true;
            }
            return false;
        }

        public static bool DecodeAddImm64(uint insn, out int rd, out int rn, out ulong imm)
        {
            rd = 0;
            rn = 0;
            imm = 0;

            // ADD 64-bit immediate: [31]=1, [30:23]=00100010, [22]=shift, [21:10]=imm12, [9:5]=Rn, [4:0]=Rd
            if ((insn & 0xFF800000) == 0x91000000 || (insn & 0xFF800000) == 0x91400000)
            {
                rd = (int)(insn & 0x1F);
                rn = (int)((insn >> 5) & 0x1F);
                imm = (insn >> 10) & 0xFFF;
                if ((insn & (1 << 22)) != 0)
                    imm <<= 12;
                return true;
            }
            return false;
        }

        public static bool DecodeLdrImm64(uint insn, out int rd, out int rn, out ulong imm)
        {
            rd = 0;
            rn = 0;
            imm = 0;

            // LDR 64-bit unsigned offset: [31:22]=1111100101, [21:10]=imm12, [9:5]=Rn, [4:0]=Rd
            if ((insn & 0xFFC00000) == 0xF9400000)
            {
                rd = (int)(insn & 0x1F);
                rn = (int)((insn >> 5) & 0x1F);
                imm = ((insn >> 10) & 0xFFF) * 8;
                return true;
            }
            return false;
        }

        public static bool IsBranchLink(uint insn)
        {
            // BL: [31:26]=001001 (0x94000000)
            if ((insn & 0xFC000000) == 0x94000000)
                return true;

            // BLR: [31:0] == 0xD63F0000
            if ((insn & 0xFFFFFC1F) == 0xD63F0000)
                return true;

            return false;
        }

        public static bool IsValidRegistrationPair(Il2Cpp il2Cpp, ulong codeReg, ulong metaReg)
        {
            try
            {
                // Must be distinct non-zero addresses
                if (codeReg == 0 || metaReg == 0 || codeReg == metaReg)
                    return false;

                ulong crOffset = il2Cpp.MapVATR(codeReg);
                ulong mrOffset = il2Cpp.MapVATR(metaReg);

                if (crOffset == 0 || mrOffset == 0 || crOffset >= il2Cpp.Length || mrOffset >= il2Cpp.Length)
                    return false;

                // Validate MetadataRegistration struct layout:
                // {
                //   int32_t genericClassesCount;       // 0
                //   void* genericClasses;              // 8
                //   int32_t genericInstsCount;         // 16
                //   void* genericInsts;                // 24
                //   int32_t genericMethodTableCount;   // 32
                //   void* genericMethodTable;          // 40
                //   int32_t typesCount;                // 48 (or 40)
                //   void* types;                       // 56
                // }
                il2Cpp.Position = mrOffset;
                int genericClassesCount = il2Cpp.ReadInt32();
                if (genericClassesCount < 0 || genericClassesCount > 2000000)
                    return false;

                il2Cpp.Position = mrOffset + 16;
                int genericInstsCount = il2Cpp.ReadInt32();
                if (genericInstsCount < 0 || genericInstsCount > 2000000)
                    return false;

                il2Cpp.Position = mrOffset + 32;
                int genericMethodTableCount = il2Cpp.ReadInt32();
                if (genericMethodTableCount < 0 || genericMethodTableCount > 2000000)
                    return false;

                // Read typesCount at 48 (or 40 depending on structure packing)
                il2Cpp.Position = mrOffset + 48;
                long typesCount = il2Cpp.ReadInt64();
                ulong typesPtr = il2Cpp.ReadUInt64();

                if (typesCount <= 0 || typesCount > 2000000)
                {
                    il2Cpp.Position = mrOffset + 40;
                    typesCount = il2Cpp.ReadInt32();
                    typesPtr = il2Cpp.ReadUInt64();
                }

                if (typesCount < 5 || typesCount > 2000000)
                    return false;

                // Validate that typesPtr maps to a readable pointer table
                if (typesPtr != 0)
                {
                    ulong typesOffset = il2Cpp.MapVATR(typesPtr);
                    if (typesOffset == 0 || typesOffset >= il2Cpp.Length)
                        return false;
                }

                // Validate CodeRegistration struct layout:
                // Check that first count is a reasonable number
                il2Cpp.Position = crOffset;
                long codeVal0 = il2Cpp.ReadInt64();
                if (codeVal0 < 0 || codeVal0 > 2000000)
                    return false;

                return true;
            }
            catch
            {
                return false;
            }
        }

        private static List<(ulong offset, ulong size, ulong vaddr)> GetExecutableSections(Il2Cpp il2Cpp)
        {
            var sections = new List<(ulong offset, ulong size, ulong vaddr)>();

            if (il2Cpp is Elf64 elf64)
            {
                var phdrs = (Elf64_Phdr[])typeof(Elf64).GetField("programSegment",
                    System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)?.GetValue(elf64);

                if (phdrs != null)
                {
                    foreach (var phdr in phdrs)
                    {
                        // PT_LOAD (1) and PF_X (1)
                        if (phdr.p_type == 1 && (phdr.p_flags & 1) != 0 && phdr.p_filesz > 0)
                        {
                            sections.Add((phdr.p_offset, phdr.p_filesz, phdr.p_vaddr));
                        }
                    }
                }
            }
            else if (il2Cpp is Macho64 macho64)
            {
                var mSections = (MachoSection64Bit[])typeof(Macho64).GetField("sections",
                    System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)?.GetValue(macho64);

                if (mSections != null)
                {
                    foreach (var s in mSections)
                    {
                        if (s.sectname == "__text" && s.size > 0)
                        {
                            sections.Add((s.offset, s.size, s.addr));
                        }
                    }
                }
            }
            else if (il2Cpp is NSO nso)
            {
                var segments = (List<NSOSegmentHeader>)typeof(NSO).GetField("segments",
                    System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)?.GetValue(nso);

                if (segments != null && segments.Count > 0)
                {
                    // Segment 0 is TextSegment in NSO
                    sections.Add((segments[0].FileOffset, segments[0].DecompressedSize, segments[0].MemoryOffset));
                }
            }

            return sections;
        }
    }
}
