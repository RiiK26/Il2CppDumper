using System;
using System.Collections.Generic;

namespace Il2CppDumper
{
    /// <summary>
    /// Handles both Decryption and Structural Layout Reconstruction for Pixel Gun 3D metadata:
    /// 1. Decryption: Multi-seeded 64-bit XorShift PRNG with a custom 256-byte substitution table (S-Box)
    ///    applied to the 0x45C header and 7 distinct metadata tables.
    /// 2. Deobfuscation & Unpacking: Converts proprietary 82-byte TypeDefinition structures into standard
    ///    Unity 88-byte TypeDefinitions (v29), maps 145 Image/module definitions, and produces a valid standard
    ///    global-metadata.dat buffer consumable by Il2CppDumper.
    /// </summary>
    public class PixelGun3DDeobfuscator : ICustomMetadataDeobfuscator
    {
        public string Name => "Pixel Gun 3D Decryptor & Metadata Unpacker (S-Box XorShift64 + 82b TypeDef Conversion)";
        public int Priority => 10;

        bool ICustomMetadataDeobfuscator.IsMatch(byte[] rawBytes) => IsMatch(rawBytes);
        bool ICustomMetadataDeobfuscator.TryDeobfuscate(byte[] rawBytes, out byte[] result, out string info) => TryDeobfuscate(rawBytes, out result, out info);
        public static readonly byte[] KnownSBox = new byte[]
        {
            0xB5, 0x71, 0xB9, 0xBC, 0x70, 0xFD, 0x5B, 0x9B, 0x76, 0x3C, 0x8F, 0x18, 0xE2, 0xB8, 0x6A, 0xFC,
            0x26, 0x7C, 0x5F, 0xFE, 0x85, 0x7E, 0x6C, 0xC5, 0x6D, 0x7B, 0x81, 0x1E, 0x06, 0x60, 0xF3, 0x62,
            0xCD, 0x88, 0xD6, 0x34, 0xD7, 0xA1, 0xD3, 0x95, 0xD2, 0xE8, 0x35, 0xC4, 0x3E, 0x40, 0xF8, 0xE9,
            0x66, 0x17, 0x29, 0xC8, 0xB4, 0x46, 0xDA, 0xA4, 0x0B, 0xDF, 0x6E, 0xE3, 0xF5, 0x87, 0x92, 0xFF,
            0xB3, 0x8D, 0xD5, 0x86, 0x16, 0x89, 0xC6, 0xC2, 0xF9, 0xC1, 0x7F, 0x21, 0x19, 0x97, 0x74, 0x84,
            0x9F, 0x55, 0xBE, 0xA2, 0xBF, 0x0A, 0x07, 0x72, 0xB7, 0xA8, 0xAE, 0xDC, 0x6B, 0x0F, 0xAD, 0xEE,
            0x25, 0x00, 0x3F, 0x53, 0x5E, 0x2A, 0xD9, 0xA9, 0x61, 0x20, 0xF1, 0x4E, 0xA7, 0x5C, 0x02, 0x03,
            0xAA, 0x96, 0x5A, 0x12, 0x9E, 0x49, 0x6F, 0x10, 0xCE, 0x30, 0x14, 0x0D, 0x51, 0x4C, 0xDE, 0x1A,
            0xFB, 0x09, 0x36, 0x41, 0x32, 0x58, 0x94, 0x1B, 0x31, 0x3A, 0xEA, 0x39, 0xBD, 0xED, 0x77, 0x56,
            0x79, 0x2C, 0xBB, 0x78, 0x99, 0x50, 0x11, 0x38, 0xA0, 0x1C, 0x05, 0x91, 0x8E, 0xC7, 0x3B, 0xFA,
            0x43, 0x69, 0x48, 0xB6, 0xE1, 0x37, 0x54, 0x08, 0xA5, 0x83, 0x45, 0xAC, 0x93, 0xA6, 0x4A, 0xD1,
            0x4F, 0xCA, 0x2D, 0xCC, 0x33, 0x0C, 0xE7, 0x24, 0x22, 0xF6, 0x5D, 0x82, 0xE5, 0xF2, 0x80, 0xBA,
            0xCB, 0x44, 0x2F, 0xF7, 0x90, 0x64, 0x9C, 0xDB, 0x63, 0x68, 0xCF, 0xF0, 0x27, 0xB2, 0xEF, 0x28,
            0x42, 0x2B, 0xE6, 0x65, 0xA3, 0xDD, 0xAB, 0x8A, 0xEC, 0xC3, 0x52, 0xB1, 0x0E, 0xD0, 0x7D, 0x1D,
            0x04, 0xD8, 0xB0, 0x8C, 0x7A, 0x98, 0x47, 0x3D, 0x8B, 0x9D, 0x1F, 0xEB, 0x9A, 0x75, 0x4D, 0xC9,
            0x67, 0x73, 0x01, 0xD4, 0x13, 0x2E, 0x4B, 0x59, 0x23, 0xE4, 0x15, 0xF4, 0x57, 0xE0, 0xC0, 0xAF
        };

        public static bool IsMatch(byte[] rawBytes)
        {
            if (rawBytes == null || rawBytes.Length < 0x45C)
                return false;

            byte[] testHdr = new byte[16];
            Array.Copy(rawBytes, testHdr, 16);
            DecryptBuffer(testHdr, 0, 16, 0x4B2F264EBE63E6EFUL, KnownSBox);

            uint testMagic = BitConverter.ToUInt32(testHdr, 0);
            return testMagic == 0x016F5270;
        }

        public static bool TryDeobfuscate(byte[] rawBytes, out byte[] result, out string info)
        {
            result = null;
            info = null;

            if (!IsMatch(rawBytes))
                return false;

            try
            {
                byte[] fullMeta = (byte[])rawBytes.Clone();

                // 1. Decrypt 0x45C header
                byte[] hdr = new byte[0x45C];
                Array.Copy(fullMeta, hdr, 0x45C);
                DecryptBuffer(hdr, 0, 0x45C, 0x4B2F264EBE63E6EFUL, KnownSBox);

                // 2. Decrypt 7 tables
                var tables = new (int szOff, int posOff, int adj, ulong seed, string name)[]
                {
                    (0x404, 0x3FC, 0x5B8, 0xCE95221D83AB368FUL, "Assemblies"),
                    (0x2C0, 0x2B8, -0x800, 0x1CB57F2820593D8CUL, "Methods"),
                    (0x41C, 0x414, 0xA0, 0x6EEEAEC7386673DEUL, "StringLiteralData"),
                    (0x3B0, 0x3A8, 0x2BC, 0xA3052110067B4998UL, "Fields"),
                    (0x1E8, 0x1E0, 0x1128, 0x86B5A56626F5BA62UL, "StringLiterals"),
                    (0x2F0, 0x2E8, 0x15C0, 0x71B89F4648850532UL, "Strings"),
                    (0x314, 0x30C, -0x5FC, 0x5E9FD334F32196BBUL, "Properties"),
                };

                foreach (var (szOff, posOff, adj, seed, _) in tables)
                {
                    int size = (int)BitConverter.ToUInt32(hdr, szOff);
                    int pos = (int)BitConverter.ToUInt32(hdr, posOff) + adj;
                    if (pos >= 0 && pos + size <= fullMeta.Length)
                    {
                        DecryptBuffer(fullMeta, pos, size, seed, KnownSBox);
                    }
                }

                // 3. Convert 82-byte TypeDefinition to 88-byte (v29)
                int typeCount = (int)BitConverter.ToUInt32(hdr, 0x364);
                if (typeCount == 0) typeCount = 33945;
                int srcOff = 0x172C1B0;
                byte[] convertedTypes = new byte[typeCount * 88];

                for (int i = 0; i < typeCount; i++)
                {
                    int inBase = srcOff + i * 82;
                    int outBase = i * 88;

                    int nameIdx = BitConverter.ToInt32(fullMeta, inBase + 0);
                    int nsIdx = BitConverter.ToInt32(fullMeta, inBase + 4);
                    int byvalIdx = BitConverter.ToInt32(fullMeta, inBase + 8);
                    int declIdx = BitConverter.ToInt32(fullMeta, inBase + 12);
                    int parentIdx = BitConverter.ToInt32(fullMeta, inBase + 16);
                    int genIdx = BitConverter.ToInt32(fullMeta, inBase + 20);
                    ushort flags = BitConverter.ToUInt16(fullMeta, inBase + 0x18);

                    BitConverter.GetBytes(nameIdx).CopyTo(convertedTypes, outBase + 0);
                    BitConverter.GetBytes(nsIdx).CopyTo(convertedTypes, outBase + 4);
                    BitConverter.GetBytes(byvalIdx).CopyTo(convertedTypes, outBase + 8);
                    BitConverter.GetBytes(declIdx).CopyTo(convertedTypes, outBase + 12);
                    BitConverter.GetBytes(parentIdx).CopyTo(convertedTypes, outBase + 16);
                    BitConverter.GetBytes(-1).CopyTo(convertedTypes, outBase + 20); // elementTypeIndex = -1
                    BitConverter.GetBytes(genIdx).CopyTo(convertedTypes, outBase + 24);
                    BitConverter.GetBytes((uint)flags).CopyTo(convertedTypes, outBase + 28);

                    // Starts: 8 ints (32 bytes)
                    Array.Copy(fullMeta, inBase + 0x1A, convertedTypes, outBase + 32, 32);

                    // Counts: 8 ushorts (16 bytes)
                    Array.Copy(fullMeta, inBase + 0x3A, convertedTypes, outBase + 64, 16);

                    // bitfield, token (8 bytes)
                    Array.Copy(fullMeta, inBase + 0x4A, convertedTypes, outBase + 80, 8);
                }

                // 4. Scan for "<Module>" to map images
                int stringsPos = 0x212830;
                var modules = new List<int>();
                for (int i = 0; i < typeCount; i++)
                {
                    int nameIdx = BitConverter.ToInt32(convertedTypes, i * 88);
                    int sOff = stringsPos + nameIdx;
                    if (sOff >= 0 && sOff + 8 < fullMeta.Length)
                    {
                        if (fullMeta[sOff] == (byte)'<' &&
                            fullMeta[sOff + 1] == (byte)'M' &&
                            fullMeta[sOff + 2] == (byte)'o' &&
                            fullMeta[sOff + 3] == (byte)'d' &&
                            fullMeta[sOff + 4] == (byte)'u' &&
                            fullMeta[sOff + 5] == (byte)'l' &&
                            fullMeta[sOff + 6] == (byte)'e' &&
                            fullMeta[sOff + 7] == (byte)'>' &&
                            fullMeta[sOff + 8] == 0)
                        {
                            modules.Add(i);
                        }
                    }
                }

                // 5. Convert images (36-byte to 40-byte v29)
                int imageCount = 145;
                int imgSrcOff = 0x19D3AB4;
                byte[] convertedImages = new byte[imageCount * 40];

                for (int i = 0; i < imageCount; i++)
                {
                    int inImgBase = imgSrcOff + i * 36;
                    int outImgBase = i * 40;

                    uint nameIdx = BitConverter.ToUInt32(fullMeta, inImgBase + 0);
                    uint assemblyIdx = BitConverter.ToUInt32(fullMeta, inImgBase + 4);
                    uint exportedTypeStart = BitConverter.ToUInt32(fullMeta, inImgBase + 12);
                    uint exportedTypeCount = BitConverter.ToUInt32(fullMeta, inImgBase + 16);
                    uint entryPoint = BitConverter.ToUInt32(fullMeta, inImgBase + 20);
                    uint token = BitConverter.ToUInt32(fullMeta, inImgBase + 24);

                    int typeStart;
                    int typeCountImg;
                    if (i < modules.Count)
                    {
                        typeStart = modules[i];
                        typeCountImg = ((i + 1 < modules.Count) ? modules[i + 1] : typeCount) - typeStart;
                    }
                    else
                    {
                        typeStart = typeCount;
                        typeCountImg = 0;
                    }

                    BitConverter.GetBytes(nameIdx).CopyTo(convertedImages, outImgBase + 0);
                    BitConverter.GetBytes(assemblyIdx).CopyTo(convertedImages, outImgBase + 4);
                    BitConverter.GetBytes((uint)typeStart).CopyTo(convertedImages, outImgBase + 8);
                    BitConverter.GetBytes((uint)typeCountImg).CopyTo(convertedImages, outImgBase + 12);
                    BitConverter.GetBytes(exportedTypeStart).CopyTo(convertedImages, outImgBase + 16);
                    BitConverter.GetBytes(exportedTypeCount).CopyTo(convertedImages, outImgBase + 20);
                    BitConverter.GetBytes(entryPoint).CopyTo(convertedImages, outImgBase + 24);
                    BitConverter.GetBytes(token).CopyTo(convertedImages, outImgBase + 28);
                    BitConverter.GetBytes(0xFFFFFFFFu).CopyTo(convertedImages, outImgBase + 32); // customAttributeStart
                    BitConverter.GetBytes(0u).CopyTo(convertedImages, outImgBase + 36);          // customAttributeCount
                }

                // 6. Assemble reconstructed v29 metadata buffer
                int origLen = fullMeta.Length;
                int newTypedefPos = origLen;
                int newTypedefSize = convertedTypes.Length;
                int newImgPos = origLen + newTypedefSize;
                int newImgSize = convertedImages.Length;

                byte[] reconstructed = new byte[origLen + newTypedefSize + newImgSize];
                Array.Copy(fullMeta, reconstructed, origLen);
                Array.Copy(convertedTypes, 0, reconstructed, newTypedefPos, newTypedefSize);
                Array.Copy(convertedImages, 0, reconstructed, newImgPos, newImgSize);

                // 7. Write standard v29 header (512 bytes / 128 uints)
                uint[] headerList = new uint[128];
                headerList[0] = 0xFAB11BAF; // sanity
                headerList[1] = 29;         // version
                headerList[2] = 0x12F0;     // stringLiteralOffset
                headerList[3] = 0x36CBC;    // stringLiteralSize
                headerList[4] = 0x37FAC;    // stringLiteralDataOffset
                headerList[5] = 0x1DA881;   // stringLiteralDataSize
                headerList[6] = 0x212830;   // stringOffset
                headerList[7] = 0x53841D;   // stringSize
                headerList[8] = 0x74AC50;   // eventsOffset
                headerList[9] = 0xD5D8;     // eventsSize
                headerList[10] = 0x758228;  // propertiesOffset
                headerList[11] = 0xC3690;   // propertiesSize
                headerList[12] = 0x81B8B8;  // methodsOffset
                headerList[13] = 0x7151C0;  // methodsSize
                headerList[22] = 0xF30A80;  // parametersOffset
                headerList[23] = 0x13C658C - 0xF30A80; // parametersSize
                headerList[24] = 0x13C658C; // fieldsOffset
                headerList[25] = 0x1C28B8;  // fieldsSize
                headerList[40] = (uint)newTypedefPos;
                headerList[41] = (uint)newTypedefSize;
                headerList[42] = (uint)newImgPos;
                headerList[43] = (uint)newImgSize;
                headerList[44] = 0x19D4F18; // assembliesOffset
                headerList[45] = 0x2684;    // assembliesSize

                for (int i = 0; i < headerList.Length; i++)
                {
                    BitConverter.GetBytes(headerList[i]).CopyTo(reconstructed, i * 4);
                }

                result = reconstructed;
                info = $"Pixel Gun 3D custom encrypted metadata detected. Decrypted 7 tables, converted {typeCount} TypeDefinitions (82->88 byte) and {imageCount} Images ({modules.Count} modules mapped), generated standard v29 metadata buffer ({reconstructed.Length} bytes).";
                return true;
            }
            catch (Exception ex)
            {
                info = $"Pixel Gun 3D deobfuscator failed: {ex.Message}";
                return false;
            }
        }

        public static void DecryptBuffer(byte[] buf, int offset, int size, ulong seed, byte[] sbox)
        {
            ulong state = seed;
            for (int i = 0; i < size; i++)
            {
                state = state ^ (state << 13);
                state = state ^ (state >> 7);
                state = state ^ (state << 17);

                ulong rax = state;
                rax = (rax >> 8) ^ state;
                rax = (rax >> 8) ^ state;
                rax = (rax >> 8) ^ state;
                byte al = (byte)(rax & 0xFF);
                byte k = sbox[al];
                buf[offset + i] ^= k;
            }
        }
    }
}
