namespace Il2CppDumper
{
    public class Config
    {
        public bool DumpMethod { get; set; } = true;
        public bool DumpField { get; set; } = true;
        public bool DumpProperty { get; set; } = true;
        public bool DumpAttribute { get; set; } = true;
        public bool DumpFieldOffset { get; set; } = true;
        public bool DumpMethodOffset { get; set; } = true;
        public bool DumpTypeDefIndex { get; set; } = true;
        public bool GenerateDummyDll { get; set; } = true;
        public bool GenerateStruct { get; set; } = true;
        public bool DummyDllAddToken { get; set; } = true;
        public bool RequireAnyKey { get; set; } = true;
        public bool ForceIl2CppVersion { get; set; } = false;
        public double ForceVersion { get; set; } = 24.3;
        public bool ForceDump { get; set; } = false;
        public bool NoRedirectedPointer { get; set; } = false;
        public bool DeobfuscateNames { get; set; } = true;
        public bool AutoDeobfuscateMetadata { get; set; } = true;
        public bool DisableMetadataSanityCheck { get; set; } = false;
        public string MetadataXorKey { get; set; } = null;
        public long MetadataShiftOffset { get; set; } = -1;
        public bool AutoRemapMemoryDump { get; set; } = true;
        public ulong MetadataMemoryBase { get; set; } = 0;
        public bool EnablePointerDensityScanner { get; set; } = true;
        public double PointerDensityThreshold { get; set; } = 0.80;
        public bool EnableStringCrossReferencer { get; set; } = true;
        public bool EnableMethodXrefs { get; set; } = true;
    }
}
