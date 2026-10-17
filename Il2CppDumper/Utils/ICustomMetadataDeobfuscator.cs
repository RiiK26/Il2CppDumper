using System;

namespace Il2CppDumper
{
    public interface ICustomMetadataDeobfuscator
    {
        string Name { get; }
        int Priority { get; }
        bool IsMatch(byte[] rawBytes);
        bool TryDeobfuscate(byte[] rawBytes, out byte[] result, out string info);
    }
}
