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

                static int Align4(int val) => (val + 3) & ~3;
                static int GetSize(byte[] h, int off, int fallback)
                {
                    int s = (int)BitConverter.ToUInt32(h, off);
                    return s > 0 ? s : fallback;
                }

                // 2. Dynamically calculate contiguous table offsets from 0x45C header sizes
                int cur = 0x12F0;
                int stringLiteralOffset = cur; int stringLiteralSize = GetSize(hdr, 0x1E8, 0x36CBC); cur = Align4(cur + stringLiteralSize);
                int stringLiteralDataOffset = cur; int stringLiteralDataSize = GetSize(hdr, 0x41C, 0x1DA881); cur = Align4(cur + stringLiteralDataSize);
                int stringOffset = cur; int stringSize = GetSize(hdr, 0x2F0, 0x53841D); cur = Align4(cur + stringSize);
                int eventsOffset = cur; int eventsSize = GetSize(hdr, 0x0F8, 0xD5D8); cur = Align4(cur + eventsSize);
                int propertiesOffset = cur; int propertiesSize = GetSize(hdr, 0x314, 0xC3690); cur = Align4(cur + propertiesSize);
                int methodsOffset = cur; int methodsSize = GetSize(hdr, 0x2C0, 0x7151C0); cur = Align4(cur + methodsSize);
                int parameterDefaultValuesOffset = cur; int parameterDefaultValuesSize = GetSize(hdr, 0x1D0, 0x12564); cur = Align4(cur + parameterDefaultValuesSize);
                int fieldDefaultValuesOffset = cur; int fieldDefaultValuesSize = GetSize(hdr, 0x458, 0x5E41C); cur = Align4(cur + fieldDefaultValuesSize);
                int rawDefaultValueDataSize = GetSize(hdr, 0x020, 0x1BC6FC);
                int fieldAndParameterDefaultValueDataOffset = (cur + 4 < fullMeta.Length && BitConverter.ToUInt32(fullMeta, cur) == 0) ? cur + 4 : cur;
                int fieldAndParameterDefaultValueDataSize = fieldAndParameterDefaultValueDataOffset > cur ? rawDefaultValueDataSize - 4 : rawDefaultValueDataSize;
                cur = Align4(fieldAndParameterDefaultValueDataOffset + fieldAndParameterDefaultValueDataSize);
                int fieldMarshaledSizesOffset = cur; int fieldMarshaledSizesSize = GetSize(hdr, 0x308, 0x23AFC); cur = Align4(cur + fieldMarshaledSizesSize);
                int parametersOffset = cur; int parametersSize = GetSize(hdr, 0x260, 0x244F98);
                if (parametersSize == 0x244F98) parametersSize = 0x244F9C;
                cur = Align4(cur + parametersSize);
                int fieldsOffset = cur; int fieldsSize = GetSize(hdr, 0x3B0, 0x1C28B8); cur = Align4(cur + fieldsSize);
                int genericParametersOffset = cur; int genericParametersSize = GetSize(hdr, 0x38C, 0x12C82); cur = Align4(cur + genericParametersSize);
                int genericParameterConstraintsOffset = cur; int genericParameterConstraintsSize = GetSize(hdr, 0x038, 0x17B4); cur = Align4(cur + genericParameterConstraintsSize);
                int genericContainersOffset = cur; int genericContainersSize = GetSize(hdr, 0x23C, 0xE9E0); cur = Align4(cur + genericContainersSize);
                int nestedTypesOffset = cur; int nestedTypesSize = GetSize(hdr, 0x05C, 0xB488); cur = Align4(cur + nestedTypesSize);
                int interfacesOffset = cur; int interfacesSize = GetSize(hdr, 0x320, 0xB84C); cur = Align4(cur + interfacesSize);
                int vtableMethodsOffset = cur; int vtableMethodsSize = GetSize(hdr, 0x2B4, 0x132F48); cur = Align4(cur + vtableMethodsSize);
                int interfaceOffsetsOffset = cur; int interfaceOffsetsSize = GetSize(hdr, 0x428, 0x36938); cur = Align4(cur + interfaceOffsetsSize);

                int typeCount = (int)BitConverter.ToUInt32(hdr, 0x364);
                if (typeCount == 0) typeCount = 33945;
                int typeDefinitionsSrcOffset = cur;
                int typeDefinitionsSrcSize = typeCount * 82;
                cur = Align4(cur + typeDefinitionsSrcSize);

                int imageCount = (int)BitConverter.ToUInt32(hdr, 0x280);
                if (imageCount == 0) imageCount = 145;
                int imagesSrcOffset = cur;
                int imagesSrcSize = imageCount * 36;
                cur = Align4(cur + imagesSrcSize);

                int assembliesOffset = cur; int assembliesSize = GetSize(hdr, 0x404, 0x2684); cur = Align4(cur + assembliesSize);
                int fieldRefsOffset = cur; int fieldRefsSize = GetSize(hdr, 0x248, 0xCAA8); cur = Align4(cur + fieldRefsSize);
                int referencedAssembliesOffset = cur; int referencedAssembliesSize = GetSize(hdr, 0x2A8, 0xD24); cur = Align4(cur + referencedAssembliesSize);
                int attributeDataOffset = cur; int attributeDataSize = GetSize(hdr, 0x188, 0x178BE0); cur = Align4(cur + attributeDataSize);
                int attributeDataRangeOffset = cur; int attributeDataRangeSize = GetSize(hdr, 0x35C, 0xA6DD8); cur = Align4(cur + attributeDataRangeSize);
                int unresolvedTypesOffset = cur; int unresolvedTypesSize = GetSize(hdr, 0x0EC, 0x12014); cur = Align4(cur + unresolvedTypesSize);
                int unresolvedRangesOffset = cur; int unresolvedRangesSize = GetSize(hdr, 0x104, 0x3768); cur = Align4(cur + unresolvedRangesSize);
                int exportedTypesOffset = cur; int exportedTypesSize = GetSize(hdr, 0x44C, 0x3194); cur = Align4(cur + exportedTypesSize);

                // 3. Decrypt 7 encrypted tables using dynamically calculated offsets
                var encryptedTables = new (int pos, int size, ulong seed, string name)[]
                {
                    (assembliesOffset, assembliesSize, 0xCE95221D83AB368FUL, "Assemblies"),
                    (methodsOffset, methodsSize, 0x1CB57F2820593D8CUL, "Methods"),
                    (stringLiteralDataOffset, stringLiteralDataSize, 0x6EEEAEC7386673DEUL, "StringLiteralData"),
                    (fieldsOffset, fieldsSize, 0xA3052110067B4998UL, "Fields"),
                    (stringLiteralOffset, stringLiteralSize, 0x86B5A56626F5BA62UL, "StringLiterals"),
                    (stringOffset, stringSize, 0x71B89F4648850532UL, "Strings"),
                    (propertiesOffset, propertiesSize, 0x5E9FD334F32196BBUL, "Properties"),
                };

                foreach (var (pos, size, seed, _) in encryptedTables)
                {
                    if (pos >= 0 && pos + size <= fullMeta.Length)
                    {
                        DecryptBuffer(fullMeta, pos, size, seed, KnownSBox);
                    }
                }

                // 4. Un-shuffle MethodDefinitions (32 bytes) from PG3D packed layout to standard v29 layout
                int methodCount = methodsSize / 32;
                byte[] convertedMethods = new byte[methodsSize];
                for (int i = 0; i < methodCount; i++)
                {
                    int inBase = methodsOffset + i * 32;
                    int outBase = i * 32;

                    uint nameIdx = BitConverter.ToUInt32(fullMeta, inBase + 0);
                    int declaringType = BitConverter.ToUInt16(fullMeta, inBase + 4);
                    int returnType = (int)BitConverter.ToUInt32(fullMeta, inBase + 6);
                    int paramStart = BitConverter.ToInt32(fullMeta, inBase + 14);
                    int genContainer = (int)(short)BitConverter.ToInt16(fullMeta, inBase + 18);
                    uint token = BitConverter.ToUInt32(fullMeta, inBase + 20);
                    ushort flags = BitConverter.ToUInt16(fullMeta, inBase + 24);
                    ushort iflags = BitConverter.ToUInt16(fullMeta, inBase + 26);
                    ushort slot = BitConverter.ToUInt16(fullMeta, inBase + 28);
                    ushort paramCount = BitConverter.ToUInt16(fullMeta, inBase + 30);

                    BitConverter.GetBytes(nameIdx).CopyTo(convertedMethods, outBase + 0);
                    BitConverter.GetBytes(declaringType).CopyTo(convertedMethods, outBase + 4);
                    BitConverter.GetBytes(returnType).CopyTo(convertedMethods, outBase + 8);
                    BitConverter.GetBytes(paramStart).CopyTo(convertedMethods, outBase + 12);
                    BitConverter.GetBytes(genContainer).CopyTo(convertedMethods, outBase + 16);
                    BitConverter.GetBytes(token).CopyTo(convertedMethods, outBase + 20);
                    BitConverter.GetBytes(flags).CopyTo(convertedMethods, outBase + 24);
                    BitConverter.GetBytes(iflags).CopyTo(convertedMethods, outBase + 26);
                    BitConverter.GetBytes(slot).CopyTo(convertedMethods, outBase + 28);
                    BitConverter.GetBytes(paramCount).CopyTo(convertedMethods, outBase + 30);
                }
                convertedMethods.CopyTo(fullMeta, methodsOffset);

                // 5. Un-swap ParameterDefinitions (12 bytes: PG3D [name, type, token] -> standard v29 [name, token, type])
                int paramDefCount = parametersSize / 12;
                for (int i = 0; i < paramDefCount; i++)
                {
                    int pBase = parametersOffset + i * 12;
                    uint typeIndex = BitConverter.ToUInt32(fullMeta, pBase + 4);
                    uint token = BitConverter.ToUInt32(fullMeta, pBase + 8);
                    BitConverter.GetBytes(token).CopyTo(fullMeta, pBase + 4);
                    BitConverter.GetBytes(typeIndex).CopyTo(fullMeta, pBase + 8);
                }

                // 6. Convert 82-byte TypeDefinition to 88-byte (v29)
                byte[] convertedTypes = new byte[typeCount * 88];
                for (int i = 0; i < typeCount; i++)
                {
                    int inBase = typeDefinitionsSrcOffset + i * 82;
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

                // 7. Scan for "<Module>" to map images
                var modules = new List<int>();
                for (int i = 0; i < typeCount; i++)
                {
                    int nameIdx = BitConverter.ToInt32(convertedTypes, i * 88);
                    int sOff = stringOffset + nameIdx;
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

                // 8. Convert images (36-byte to 40-byte v29)
                byte[] convertedImages = new byte[imageCount * 40];
                for (int i = 0; i < imageCount; i++)
                {
                    int inImgBase = imagesSrcOffset + i * 36;
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

                // 9. Convert generic parameters (14-byte PG3D to 16-byte standard v29)
                int genericParamCount = genericParametersSize / 14;
                byte[] convertedGenericParams = new byte[genericParamCount * 16];
                for (int i = 0; i < genericParamCount; i++)
                {
                    int inBase = genericParametersOffset + i * 14;
                    int outBase = i * 16;
                    ushort ownerIndex = BitConverter.ToUInt16(fullMeta, inBase + 0);
                    uint nameIndex = BitConverter.ToUInt32(fullMeta, inBase + 2);
                    short constraintsStart = BitConverter.ToInt16(fullMeta, inBase + 6);
                    short constraintsCount = BitConverter.ToInt16(fullMeta, inBase + 8);
                    ushort num = BitConverter.ToUInt16(fullMeta, inBase + 10);
                    ushort flags = BitConverter.ToUInt16(fullMeta, inBase + 12);

                    BitConverter.GetBytes((uint)ownerIndex).CopyTo(convertedGenericParams, outBase + 0);
                    BitConverter.GetBytes(nameIndex).CopyTo(convertedGenericParams, outBase + 4);
                    BitConverter.GetBytes(constraintsStart).CopyTo(convertedGenericParams, outBase + 8);
                    BitConverter.GetBytes(constraintsCount).CopyTo(convertedGenericParams, outBase + 10);
                    BitConverter.GetBytes(num).CopyTo(convertedGenericParams, outBase + 12);
                    BitConverter.GetBytes(flags).CopyTo(convertedGenericParams, outBase + 14);
                }

                // 10. Assemble reconstructed v29 metadata buffer
                int origLen = fullMeta.Length;
                int newTypedefPos = origLen;
                int newTypedefSize = convertedTypes.Length;
                int newImgPos = origLen + newTypedefSize;
                int newImgSize = convertedImages.Length;
                int newGenericParamPos = origLen + newTypedefSize + newImgSize;
                int newGenericParamSize = convertedGenericParams.Length;

                byte[] reconstructed = new byte[origLen + newTypedefSize + newImgSize + newGenericParamSize];
                Array.Copy(fullMeta, reconstructed, origLen);
                Array.Copy(convertedTypes, 0, reconstructed, newTypedefPos, newTypedefSize);
                Array.Copy(convertedImages, 0, reconstructed, newImgPos, newImgSize);
                Array.Copy(convertedGenericParams, 0, reconstructed, newGenericParamPos, newGenericParamSize);

                // 11. Write complete standard v29 header (128 uints / 512 bytes)
                uint[] headerList = new uint[128];
                headerList[0] = 0xFAB11BAF; // sanity
                headerList[1] = 29;         // version
                headerList[2] = (uint)stringLiteralOffset;
                headerList[3] = (uint)stringLiteralSize;
                headerList[4] = (uint)stringLiteralDataOffset;
                headerList[5] = (uint)stringLiteralDataSize;
                headerList[6] = (uint)stringOffset;
                headerList[7] = (uint)stringSize;
                headerList[8] = (uint)eventsOffset;
                headerList[9] = (uint)eventsSize;
                headerList[10] = (uint)propertiesOffset;
                headerList[11] = (uint)propertiesSize;
                headerList[12] = (uint)methodsOffset;
                headerList[13] = (uint)methodsSize;
                headerList[14] = (uint)parameterDefaultValuesOffset;
                headerList[15] = (uint)parameterDefaultValuesSize;
                headerList[16] = (uint)fieldDefaultValuesOffset;
                headerList[17] = (uint)fieldDefaultValuesSize;
                headerList[18] = (uint)fieldAndParameterDefaultValueDataOffset;
                headerList[19] = (uint)fieldAndParameterDefaultValueDataSize;
                headerList[20] = (uint)fieldMarshaledSizesOffset;
                headerList[21] = (uint)fieldMarshaledSizesSize;
                headerList[22] = (uint)parametersOffset;
                headerList[23] = (uint)parametersSize;
                headerList[24] = (uint)fieldsOffset;
                headerList[25] = (uint)fieldsSize;
                headerList[26] = (uint)newGenericParamPos;
                headerList[27] = (uint)newGenericParamSize;
                headerList[28] = (uint)genericParameterConstraintsOffset;
                headerList[29] = (uint)genericParameterConstraintsSize;
                headerList[30] = (uint)genericContainersOffset;
                headerList[31] = (uint)genericContainersSize;
                headerList[32] = (uint)nestedTypesOffset;
                headerList[33] = (uint)nestedTypesSize;
                headerList[34] = (uint)interfacesOffset;
                headerList[35] = (uint)interfacesSize;
                headerList[36] = (uint)vtableMethodsOffset;
                headerList[37] = (uint)vtableMethodsSize;
                headerList[38] = (uint)interfaceOffsetsOffset;
                headerList[39] = (uint)interfaceOffsetsSize;
                headerList[40] = (uint)newTypedefPos;
                headerList[41] = (uint)newTypedefSize;
                headerList[42] = (uint)newImgPos;
                headerList[43] = (uint)newImgSize;
                headerList[44] = (uint)assembliesOffset;
                headerList[45] = (uint)assembliesSize;
                headerList[46] = (uint)fieldRefsOffset;
                headerList[47] = (uint)fieldRefsSize;
                headerList[48] = (uint)referencedAssembliesOffset;
                headerList[49] = (uint)referencedAssembliesSize;
                headerList[50] = (uint)attributeDataOffset;
                headerList[51] = (uint)attributeDataSize;
                headerList[52] = (uint)attributeDataRangeOffset;
                headerList[53] = (uint)attributeDataRangeSize;
                headerList[54] = (uint)unresolvedTypesOffset;
                headerList[55] = (uint)unresolvedTypesSize;
                headerList[56] = (uint)unresolvedRangesOffset;
                headerList[57] = (uint)unresolvedRangesSize;
                headerList[58] = 0; // windowsRuntimeTypeNamesOffset
                headerList[59] = 0; // windowsRuntimeTypeNamesSize
                headerList[60] = 0; // windowsRuntimeStringsOffset
                headerList[61] = 0; // windowsRuntimeStringsSize
                headerList[62] = (uint)exportedTypesOffset;
                headerList[63] = (uint)exportedTypesSize;

                for (int i = 0; i < headerList.Length; i++)
                {
                    BitConverter.GetBytes(headerList[i]).CopyTo(reconstructed, i * 4);
                }

                result = reconstructed;
                info = $"Pixel Gun 3D custom encrypted metadata detected. Decrypted 7 tables, un-shuffled {methodCount} Methods & {paramDefCount} Parameters, mapped all v29 tables (Generics, Interfaces, Constants), converted {typeCount} TypeDefinitions (82->88b) & {imageCount} Images ({modules.Count} modules), generated standard v29 metadata buffer ({reconstructed.Length} bytes).";
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
