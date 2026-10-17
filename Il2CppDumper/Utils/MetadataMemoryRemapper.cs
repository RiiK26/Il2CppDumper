using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Il2CppDumper
{
    public static class MetadataMemoryRemapper
    {
        private const uint StandardMagic = 0xFAB11BAF;

        /// <summary>
        /// Checks whether the metadata file contains absolute in-memory virtual addresses (VAs)
        /// rather than relative file offsets, and computes the candidate memory base address.
        /// </summary>
        public static bool IsMemoryDump(byte[] data, out ulong detectedBase)
        {
            detectedBase = 0;
            if (data == null || data.Length < 256)
                return false;

            uint magic = BitConverter.ToUInt32(data, 0);
            if (magic != StandardMagic)
                return false;

            int version = BitConverter.ToInt32(data, 4);
            if (version < 16 || version > 200)
                return false;

            // Collect non-zero offsets from header
            var offsets = GetHeaderOffsets(data, version);
            if (offsets.Count == 0)
                return false;

            ulong dataLen = (ulong)data.Length;

            // If all offsets are already valid relative offsets within the file, it's not a memory dump
            if (offsets.All(off => off < dataLen))
                return false;

            // Offsets exceed file size: this is an in-memory dump with VAs
            ulong minOffset = offsets.Min();

            // Candidate base 1: Page-aligned (4KB or 64KB)
            ulong candidateBase1 = minOffset & ~0xFFFUL;
            if (ValidateBase(offsets, candidateBase1, dataLen))
            {
                detectedBase = candidateBase1;
                return true;
            }

            // Candidate base 2: Aligned to 0x100 / 256 bytes
            ulong candidateBase2 = minOffset & ~0xFFUL;
            if (ValidateBase(offsets, candidateBase2, dataLen))
            {
                detectedBase = candidateBase2;
                return true;
            }

            // Candidate base 3: Direct header base (minOffset - first table offset, usually 0x100..0x200)
            int[] testDeltas = { 0x100, 0x108, 0x110, 0x120, 0x180, 0x200 };
            foreach (var delta in testDeltas)
            {
                if (minOffset >= (ulong)delta)
                {
                    ulong cand = minOffset - (ulong)delta;
                    if (ValidateBase(offsets, cand, dataLen))
                    {
                        detectedBase = cand;
                        return true;
                    }
                }
            }

            return false;
        }

        /// <summary>
        /// Remaps all virtual memory addresses in the metadata header to relative file offsets.
        /// </summary>
        public static byte[] Remap(byte[] data, ulong baseAddress, out string info)
        {
            var result = (byte[])data.Clone();
            int version = BitConverter.ToInt32(result, 4);
            int remappedCount = 0;

            if (version >= 38)
            {
                // In v38+, Il2CppSectionMetadata has { int offset; int sectionSize; int count; } (12 bytes)
                // Sections start after sanity (4) and version (4) at offset 8
                for (int pos = 8; pos <= 248; pos += 12)
                {
                    if (pos + 4 <= result.Length)
                    {
                        uint off = BitConverter.ToUInt32(result, pos);
                        if (off >= baseAddress && off > 0)
                        {
                            uint remapped = (uint)(off - baseAddress);
                            BitConverter.GetBytes(remapped).CopyTo(result, pos);
                            remappedCount++;
                        }
                    }
                }
            }
            else
            {
                // In v16-v31: header layout alternates { uint offset; int size; } (8 bytes per table)
                // Starting at stringLiteralOffset (offset 8)
                int endPos = version <= 24.1 ? 184 : 176;
                for (int pos = 8; pos <= endPos; pos += 8)
                {
                    if (pos + 4 <= result.Length)
                    {
                        uint off = BitConverter.ToUInt32(result, pos);
                        if (off >= baseAddress && off > 0)
                        {
                            uint remapped = (uint)(off - baseAddress);
                            BitConverter.GetBytes(remapped).CopyTo(result, pos);
                            remappedCount++;
                        }
                    }
                }
            }

            info = $"Remapped {remappedCount} table offsets in metadata header by subtracting memory base 0x{baseAddress:X}";
            return result;
        }

        private static bool ValidateBase(List<ulong> offsets, ulong candidateBase, ulong dataLen)
        {
            if (candidateBase == 0)
                return false;

            foreach (var off in offsets)
            {
                if (off < candidateBase)
                    return false;

                ulong rel = off - candidateBase;
                if (rel >= dataLen)
                    return false;
            }

            return true;
        }

        private static List<ulong> GetHeaderOffsets(byte[] data, int version)
        {
            var list = new List<ulong>();

            if (version >= 38)
            {
                for (int pos = 8; pos <= 248; pos += 12)
                {
                    if (pos + 4 <= data.Length)
                    {
                        uint off = BitConverter.ToUInt32(data, pos);
                        if (off > 0)
                            list.Add(off);
                    }
                }
            }
            else
            {
                int endPos = version <= 24.1 ? 184 : 176;
                for (int pos = 8; pos <= endPos; pos += 8)
                {
                    if (pos + 4 <= data.Length)
                    {
                        uint off = BitConverter.ToUInt32(data, pos);
                        if (off > 0)
                            list.Add(off);
                    }
                }
            }

            return list;
        }
    }
}
