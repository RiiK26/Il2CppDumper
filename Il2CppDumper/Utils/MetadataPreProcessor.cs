using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Il2CppDumper
{
    public static class MetadataPreProcessor
    {
        private const uint StandardMagic = 0xFAB11BAF;

        private static readonly List<ICustomMetadataDeobfuscator> CustomDeobfuscators = new();

        static MetadataPreProcessor()
        {
            DiscoverDeobfuscators();
        }

        private static void DiscoverDeobfuscators()
        {
            try
            {
                var deobfuscatorInterface = typeof(ICustomMetadataDeobfuscator);
                var types = AppDomain.CurrentDomain.GetAssemblies()
                    .SelectMany(a =>
                    {
                        try { return a.GetTypes(); }
                        catch { return Array.Empty<Type>(); }
                    })
                    .Where(t => deobfuscatorInterface.IsAssignableFrom(t) && !t.IsInterface && !t.IsAbstract);

                foreach (var type in types)
                {
                    try
                    {
                        if (Activator.CreateInstance(type) is ICustomMetadataDeobfuscator instance)
                        {
                            RegisterDeobfuscator(instance);
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }

        public static void RegisterDeobfuscator(ICustomMetadataDeobfuscator deobfuscator)
        {
            if (deobfuscator != null && !CustomDeobfuscators.Any(d => d.GetType() == deobfuscator.GetType()))
            {
                CustomDeobfuscators.Add(deobfuscator);
                CustomDeobfuscators.Sort((a, b) => b.Priority.CompareTo(a.Priority));
            }
        }

        /// <summary>
        /// Processes raw metadata bytes by checking for shifts, encryptions (XOR, NOT),
        /// and corrupted magic headers, returning the sanitized metadata byte array.
        /// </summary>
        public static byte[] Process(byte[] rawBytes, Config config, out string detectedInfo)
        {
            detectedInfo = null;

            if (rawBytes == null || rawBytes.Length < 16)
            {
                return rawBytes;
            }

            // 1. Manual shift if specified by user
            if (config.MetadataShiftOffset > 0 && config.MetadataShiftOffset < rawBytes.Length)
            {
                var offset = (int)config.MetadataShiftOffset;
                detectedInfo = $"Applied manual shift offset: +0x{offset:X}";
                rawBytes = rawBytes.AsSpan(offset).ToArray();
            }

            // 2. Manual XOR key if specified by user
            if (!string.IsNullOrWhiteSpace(config.MetadataXorKey))
            {
                var key = ParseXorKey(config.MetadataXorKey);
                if (key != null && key.Length > 0)
                {
                    rawBytes = ApplyXor(rawBytes, key);
                    detectedInfo = $"Applied manual XOR key ({BitConverter.ToString(key)}): {detectedInfo}";
                }
            }

            // If magic is already valid, check for memory dump remapping
            if (BitConverter.ToUInt32(rawBytes, 0) == StandardMagic)
            {
                if (config.MetadataMemoryBase > 0)
                {
                    rawBytes = MetadataMemoryRemapper.Remap(rawBytes, config.MetadataMemoryBase, out var remapInfo);
                    detectedInfo = string.IsNullOrEmpty(detectedInfo) ? remapInfo : $"{detectedInfo}; {remapInfo}";
                }
                else if (config.AutoRemapMemoryDump)
                {
                    if (MetadataMemoryRemapper.IsMemoryDump(rawBytes, out var detectedBase))
                    {
                        rawBytes = MetadataMemoryRemapper.Remap(rawBytes, detectedBase, out var remapInfo);
                        detectedInfo = string.IsNullOrEmpty(detectedInfo) ? remapInfo : $"{detectedInfo}; {remapInfo}";
                    }
                }

                detectedInfo ??= "Valid standard metadata header found.";
                return rawBytes;
            }

            // 3. Auto-deobfuscation heuristics
            if (config.AutoDeobfuscateMetadata)
            {
                if (TryAutoDeobfuscate(rawBytes, config, out var processed, out var autoInfo))
                {
                    if (config.MetadataMemoryBase > 0)
                    {
                        processed = MetadataMemoryRemapper.Remap(processed, config.MetadataMemoryBase, out var remapInfo);
                        autoInfo = $"{autoInfo}; {remapInfo}";
                    }
                    else if (config.AutoRemapMemoryDump)
                    {
                        if (MetadataMemoryRemapper.IsMemoryDump(processed, out var detectedBase))
                        {
                            processed = MetadataMemoryRemapper.Remap(processed, detectedBase, out var remapInfo);
                            autoInfo = $"{autoInfo}; {remapInfo}";
                        }
                    }

                    detectedInfo = autoInfo;
                    return processed;
                }
            }

            return rawBytes;
        }

        /// <summary>
        /// Checks whether the given byte array appears to be a metadata file (clean, shifted, or encrypted).
        /// </summary>
        public static bool IsMetadataCandidate(byte[] rawBytes, string fileName = null)
        {
            if (rawBytes == null || rawBytes.Length < 64)
                return false;

            // Direct magic match
            if (BitConverter.ToUInt32(rawBytes, 0) == StandardMagic)
                return true;

            // File name hints
            if (!string.IsNullOrEmpty(fileName))
            {
                var name = Path.GetFileName(fileName).ToLowerInvariant();
                if (name.Contains("metadata") || name.EndsWith(".dat"))
                    return true;
            }

            // Check if standard magic is present somewhere within the first 64KB
            int searchLimit = Math.Min(rawBytes.Length - 8, 64 * 1024);
            for (int i = 1; i <= searchLimit; i++)
            {
                if (BitConverter.ToUInt32(rawBytes, i) == StandardMagic)
                {
                    int ver = BitConverter.ToInt32(rawBytes, i + 4);
                    if (ver >= 16 && ver <= 200)
                        return true;
                }
            }

            // Check if candidate matches corrupted magic with valid metadata layout
            if (VerifyHeaderLayout(rawBytes, 0, out _))
                return true;

            // Check NOT inversion
            if (~BitConverter.ToUInt32(rawBytes, 0) == StandardMagic)
                return true;

            // Check 1-byte XOR
            byte k0 = (byte)(rawBytes[0] ^ 0xAF);
            if ((rawBytes[1] ^ k0) == 0x1B && (rawBytes[2] ^ k0) == 0xB1 && (rawBytes[3] ^ k0) == 0xFA)
                return true;

            // Check wiped header reconstruction
            if (MetadataTableReconstructor.IsHeaderWiped(rawBytes))
            {
                if (MetadataTableReconstructor.TryReconstruct(rawBytes, null, out _, out _))
                    return true;
            }

            // Check registered custom game deobfuscators (e.g. Pixel Gun 3D, etc.)
            foreach (var deobfuscator in CustomDeobfuscators)
            {
                if (deobfuscator.IsMatch(rawBytes))
                    return true;
            }

            return false;
        }

        private static bool TryAutoDeobfuscate(byte[] rawBytes, Config config, out byte[] result, out string info)
        {
            result = null;
            info = null;

            // 0. Check registered custom game deobfuscators (e.g. Pixel Gun 3D, etc.)
            foreach (var deobfuscator in CustomDeobfuscators)
            {
                if (deobfuscator.IsMatch(rawBytes))
                {
                    if (deobfuscator.TryDeobfuscate(rawBytes, out var deobfuscatedBytes, out var deobfuscatedInfo))
                    {
                        info = $"[{deobfuscator.Name}] {deobfuscatedInfo}";
                        result = deobfuscatedBytes;
                        return true;
                    }
                }
            }

            // A. Check for prepended header / shifted metadata (up to first 1MB)
            int scanLimit = Math.Min(rawBytes.Length - 8, 1024 * 1024);
            for (int i = 1; i <= scanLimit; i++)
            {
                if (BitConverter.ToUInt32(rawBytes, i) == StandardMagic)
                {
                    int version = BitConverter.ToInt32(rawBytes, i + 4);
                    if (version >= 16 && version <= 200)
                    {
                        info = $"Detected shifted metadata at offset +0x{i:X} (version {version}). Sliced header.";
                        result = rawBytes.AsSpan(i).ToArray();
                        return true;
                    }
                }
            }

            // B. Bitwise NOT (inverted bytes)
            if (~BitConverter.ToUInt32(rawBytes, 0) == StandardMagic)
            {
                int version = ~BitConverter.ToInt32(rawBytes, 4);
                if (version >= 16 && version <= 200)
                {
                    var inverted = new byte[rawBytes.Length];
                    for (int i = 0; i < rawBytes.Length; i++)
                        inverted[i] = (byte)~rawBytes[i];

                    info = $"Detected bitwise-NOT inverted metadata (version {version}). Inverted bytes.";
                    result = inverted;
                    return true;
                }
            }

            // C. Single-byte XOR
            byte xor1 = (byte)(rawBytes[0] ^ 0xAF);
            if ((rawBytes[1] ^ xor1) == 0x1B && (rawBytes[2] ^ xor1) == 0xB1 && (rawBytes[3] ^ xor1) == 0xFA)
            {
                int version = (rawBytes[4] ^ xor1) |
                              ((rawBytes[5] ^ xor1) << 8) |
                              ((rawBytes[6] ^ xor1) << 16) |
                              ((rawBytes[7] ^ xor1) << 24);

                if (version >= 16 && version <= 200)
                {
                    var decrypted = ApplyXor(rawBytes, new[] { xor1 });
                    info = $"Detected 1-byte XOR encrypted metadata (key: 0x{xor1:X2}, version {version}). Decrypted.";
                    result = decrypted;
                    return true;
                }
            }

            // D. 4-byte rolling XOR
            byte[] xor4 = new byte[]
            {
                (byte)(rawBytes[0] ^ 0xAF),
                (byte)(rawBytes[1] ^ 0x1B),
                (byte)(rawBytes[2] ^ 0xB1),
                (byte)(rawBytes[3] ^ 0xFA)
            };

            int v4 = (rawBytes[4] ^ xor4[0]) |
                     ((rawBytes[5] ^ xor4[1]) << 8) |
                     ((rawBytes[6] ^ xor4[2]) << 16) |
                     ((rawBytes[7] ^ xor4[3]) << 24);

            if (v4 >= 16 && v4 <= 200)
            {
                var candidate = ApplyXor(rawBytes, xor4);
                if (VerifyHeaderLayout(candidate, 0, out _))
                {
                    info = $"Detected 4-byte rolling XOR encryption (key: 0x{xor4[3]:X2}{xor4[2]:X2}{xor4[1]:X2}{xor4[0]:X2}, version {v4}). Decrypted.";
                    result = candidate;
                    return true;
                }
            }

            // E. Corrupted / Custom Magic but intact metadata layout
            if (VerifyHeaderLayout(rawBytes, 0, out int detectedVersion))
            {
                var fixedBytes = (byte[])rawBytes.Clone();
                BitConverter.GetBytes(StandardMagic).CopyTo(fixedBytes, 0);
                info = $"Detected corrupted/custom magic (0x{BitConverter.ToUInt32(rawBytes, 0):X8}) with valid metadata structure (version {detectedVersion}). Restored standard magic.";
                result = fixedBytes;
                return true;
            }

            // F. Wiped/Zeroed Header Reconstruction
            if (MetadataTableReconstructor.IsHeaderWiped(rawBytes))
            {
                double? targetVer = config?.ForceIl2CppVersion == true ? config.ForceVersion : null;
                if (MetadataTableReconstructor.TryReconstruct(rawBytes, targetVer, out var reconstructed, out var recInfo))
                {
                    info = recInfo;
                    result = reconstructed;
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Validates whether the byte array at the given offset has a plausible global-metadata header structure.
        /// </summary>
        public static bool VerifyHeaderLayout(byte[] data, int offset, out int version)
        {
            version = 0;
            if (data == null || data.Length - offset < 256)
                return false;

            int ver = BitConverter.ToInt32(data, offset + 4);
            if (ver < 16 || ver > 200)
                return false;

            version = ver;

            // In v24+, stringLiteralOffset is at 8, stringOffset is at 16, typeDefinitionsOffset is at 48
            uint stringLiteralOffset = BitConverter.ToUInt32(data, offset + 8);
            int stringLiteralSize = BitConverter.ToInt32(data, offset + 12);
            uint stringOffset = BitConverter.ToUInt32(data, offset + 16);
            int stringSize = BitConverter.ToInt32(data, offset + 20);

            // Bounds check
            long totalLen = data.Length - offset;
            if (stringLiteralOffset > totalLen || stringOffset > totalLen)
                return false;
            if (stringLiteralSize < 0 || stringSize < 0)
                return false;

            // Verify ASCII text at stringOffset
            if (stringOffset > 0 && stringOffset + 10 < totalLen)
            {
                int sampleLen = Math.Min(stringSize > 0 ? stringSize : 512, (int)(totalLen - stringOffset));
                if (sampleLen > 16)
                {
                    var sample = Encoding.ASCII.GetString(data, (int)(offset + stringOffset), sampleLen);
                    // Check if there are common Unity/C# assembly or type names
                    if (sample.Contains("mscorlib") ||
                        sample.Contains("System") ||
                        sample.Contains("UnityEngine") ||
                        sample.Contains("Assembly") ||
                        sample.Contains("Module"))
                    {
                        return true;
                    }

                    // Count printable ASCII characters
                    int printable = sample.Count(c => c == '\0' || (c >= 32 && c <= 126));
                    if ((double)printable / sampleLen > 0.85)
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        public static byte[] ApplyXor(byte[] data, byte[] key)
        {
            if (key == null || key.Length == 0)
                return data;

            var output = new byte[data.Length];
            int keyLen = key.Length;
            for (int i = 0; i < data.Length; i++)
            {
                output[i] = (byte)(data[i] ^ key[i % keyLen]);
            }
            return output;
        }

        private static byte[] ParseXorKey(string keyStr)
        {
            keyStr = keyStr.Trim();
            if (keyStr.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                keyStr = keyStr.Substring(2);

            keyStr = keyStr.Replace(" ", "").Replace(",", "").Replace("-", "");

            if (keyStr.Length % 2 != 0)
                keyStr = "0" + keyStr;

            try
            {
                var bytes = new byte[keyStr.Length / 2];
                for (int i = 0; i < bytes.Length; i++)
                {
                    bytes[i] = Convert.ToByte(keyStr.Substring(i * 2, 2), 16);
                }
                return bytes;
            }
            catch
            {
                return null;
            }
        }
    }
}
