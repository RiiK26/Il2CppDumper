using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace Il2CppDumper
{
    class Program
    {
        private static Config config;

        [STAThread]
        static void Main(string[] args)
        {
            config = JsonSerializer.Deserialize<Config>(File.ReadAllText(AppDomain.CurrentDomain.BaseDirectory + @"config.json"));
            string il2cppPath = null;
            string metadataPath = null;
            string outputDir = null;

            var fileArgs = new List<string>();
            for (int aIdx = 0; aIdx < args.Length; aIdx++)
            {
                var arg = args[aIdx];
                if (arg == "-h" || arg == "--help" || arg == "/?" || arg == "/h")
                {
                    ShowHelp();
                    return;
                }
                else if (arg == "--version" && aIdx + 1 < args.Length)
                {
                    if (double.TryParse(args[++aIdx], System.Globalization.NumberStyles.Any, System.Globalization.CultureInfo.InvariantCulture, out var ver))
                    {
                        config.ForceIl2CppVersion = true;
                        config.ForceVersion = ver;
                    }
                }
                else if (arg == "--force-dump")
                {
                    config.ForceDump = true;
                }
                else if (arg == "--no-struct")
                {
                    config.GenerateStruct = false;
                }
                else if (arg == "--struct")
                {
                    config.GenerateStruct = true;
                }
                else if (arg == "--no-dll")
                {
                    config.GenerateDummyDll = false;
                }
                else if (arg == "--dll")
                {
                    config.GenerateDummyDll = true;
                }
                else if (File.Exists(arg))
                {
                    fileArgs.Add(arg);
                }
                else if (Directory.Exists(arg) || arg.EndsWith("/") || arg.EndsWith("\\"))
                {
                    outputDir = Path.GetFullPath(arg) + Path.DirectorySeparatorChar;
                }
                else
                {
                    // Fallback to positional file
                    fileArgs.Add(arg);
                }
            }

            if (fileArgs.Count >= 2)
            {
                ClassifyFiles(fileArgs[0], fileArgs[1], out il2cppPath, out metadataPath);
            }
            else if (fileArgs.Count == 1 && File.Exists(fileArgs[0]))
            {
                var file = File.ReadAllBytes(fileArgs[0]);
                if (IsExecutableFile(file))
                {
                    il2cppPath = fileArgs[0];
                }
                else
                {
                    metadataPath = fileArgs[0];
                }
            }
            outputDir ??= AppDomain.CurrentDomain.BaseDirectory;
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                if (il2cppPath == null)
                {
                    var ofd = new OpenFileDialog
                    {
                        Filter = "Il2Cpp binary file|*.*"
                    };
                    if (ofd.ShowDialog())
                    {
                        il2cppPath = ofd.FileName;
                        ofd.Filter = "global-metadata|global-metadata.dat";
                        if (ofd.ShowDialog())
                        {
                            metadataPath = ofd.FileName;
                        }
                        else
                        {
                            return;
                        }
                    }
                    else
                    {
                        return;
                    }
                }
            }
            if (il2cppPath == null)
            {
                ShowHelp();
                return;
            }
            if (metadataPath == null)
            {
                Console.WriteLine($"ERROR: Metadata file not found or encrypted.");
            }
            else
            {
                try
                {
                    if (Init(il2cppPath, metadataPath, out var metadata, out var il2Cpp))
                    {
                        Dump(metadata, il2Cpp, outputDir);
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                }
            }
            if (config.RequireAnyKey)
            {
                Console.WriteLine("Press any key to exit...");
                Console.ReadKey(true);
            }
        }

        static void ShowHelp()
        {
            Console.WriteLine($"usage: {AppDomain.CurrentDomain.FriendlyName} <executable-file> <global-metadata> [output-directory] [options]");
            Console.WriteLine("Options:");
            Console.WriteLine("  --version <ver>   Force IL2CPP metadata version (e.g. 24.3, 29.0)");
            Console.WriteLine("  --force-dump      Force memory dump loading");
            Console.WriteLine("  --no-struct       Skip generating C/C++ struct headers (il2cpp.h)");
            Console.WriteLine("  --struct          Force generate C/C++ struct headers");
            Console.WriteLine("  --no-dll          Skip generating DummyDll assemblies");
            Console.WriteLine("  --dll             Force generate DummyDll assemblies");
        }

        private static bool IsExecutableFile(byte[] bytes)
        {
            if (bytes == null || bytes.Length < 4) return false;
            var magic = BitConverter.ToUInt32(bytes, 0);
            return magic == 0x464c457f // ELF
                || (bytes[0] == 0x4D && bytes[1] == 0x5A) // PE (MZ)
                || magic == 0xFEEDFACE || magic == 0xFEEDFACF || magic == 0xCAFEBABE || magic == 0xBEBAFECA // Mach-O
                || magic == 0x304F534E // NSO
                || magic == 0x6D736100; // WASM
        }

        private static void ClassifyFiles(string fileA, string fileB, out string il2cppPath, out string metadataPath)
        {
            var bytesA = File.ReadAllBytes(fileA);
            var bytesB = File.ReadAllBytes(fileB);

            bool isExecA = IsExecutableFile(bytesA);
            bool isExecB = IsExecutableFile(bytesB);

            if (isExecA && !isExecB)
            {
                il2cppPath = fileA;
                metadataPath = fileB;
            }
            else if (!isExecA && isExecB)
            {
                il2cppPath = fileB;
                metadataPath = fileA;
            }
            else
            {
                bool isMetaA = MetadataPreProcessor.IsMetadataCandidate(bytesA, fileA);
                bool isMetaB = MetadataPreProcessor.IsMetadataCandidate(bytesB, fileB);

                if (isMetaA && !isMetaB)
                {
                    metadataPath = fileA;
                    il2cppPath = fileB;
                }
                else
                {
                    il2cppPath = fileA;
                    metadataPath = fileB;
                }
            }
        }

        private static bool Init(string il2cppPath, string metadataPath, out Metadata metadata, out Il2Cpp il2Cpp)
        {
            Console.WriteLine("Initializing metadata...");
            var metadataBytes = File.ReadAllBytes(metadataPath);
            if (config.AutoDeobfuscateMetadata || config.MetadataShiftOffset >= 0 || !string.IsNullOrWhiteSpace(config.MetadataXorKey))
            {
                metadataBytes = MetadataPreProcessor.Process(metadataBytes, config, out var info);
                if (!string.IsNullOrEmpty(info))
                {
                    Console.WriteLine($"[MetadataPreProcessor] {info}");
                }
            }
            double? forceVersion = config.ForceIl2CppVersion ? config.ForceVersion : null;
            metadata = new Metadata(new MemoryStream(metadataBytes), forceVersion, config.DisableMetadataSanityCheck);
            Console.WriteLine($"Metadata Version: {metadata.Version}");

            Console.WriteLine("Initializing il2cpp file...");
            var il2cppBytes = File.ReadAllBytes(il2cppPath);
            var il2cppMagic = BitConverter.ToUInt32(il2cppBytes, 0);
            var il2CppMemory = new MemoryStream(il2cppBytes);
            switch (il2cppMagic)
            {
                default:
                    throw new NotSupportedException("ERROR: il2cpp file not supported.");
                case 0x6D736100:
                    var web = new WebAssembly(il2CppMemory);
                    il2Cpp = web.CreateMemory();
                    break;
                case 0x304F534E:
                    var nso = new NSO(il2CppMemory);
                    il2Cpp = nso.UnCompress();
                    break;
                case 0x905A4D: //PE
                    il2Cpp = new PE(il2CppMemory);
                    break;
                case 0x464c457f: //ELF
                    if (il2cppBytes[4] == 2) //ELF64
                    {
                        il2Cpp = new Elf64(il2CppMemory);
                    }
                    else
                    {
                        il2Cpp = new Elf(il2CppMemory);
                    }
                    break;
                case 0xCAFEBABE: //FAT Mach-O
                case 0xBEBAFECA:
                    var machofat = new MachoFat(new MemoryStream(il2cppBytes));
                    Console.Write("Select Platform: ");
                    for (var i = 0; i < machofat.fats.Length; i++)
                    {
                        var fat = machofat.fats[i];
                        Console.Write(fat.magic == 0xFEEDFACF ? $"{i + 1}.64bit " : $"{i + 1}.32bit ");
                    }
                    Console.WriteLine();
                    var key = Console.ReadKey(true);
                    var index = int.Parse(key.KeyChar.ToString()) - 1;
                    var magic = machofat.fats[index % 2].magic;
                    il2cppBytes = machofat.GetMacho(index % 2);
                    il2CppMemory = new MemoryStream(il2cppBytes);
                    if (magic == 0xFEEDFACF)
                        goto case 0xFEEDFACF;
                    else
                        goto case 0xFEEDFACE;
                case 0xFEEDFACF: // 64bit Mach-O
                    il2Cpp = new Macho64(il2CppMemory);
                    break;
                case 0xFEEDFACE: // 32bit Mach-O
                    il2Cpp = new Macho(il2CppMemory);
                    break;
            }
            var version = config.ForceIl2CppVersion ? config.ForceVersion : metadata.Version;
            il2Cpp.SetProperties(version, metadata.metadataUsagesCount, metadata);
            Console.WriteLine($"Il2Cpp Version: {il2Cpp.Version}");
            if (config.ForceDump || il2Cpp.CheckDump())
            {
                if (il2Cpp is ElfBase elf)
                {
                    Console.WriteLine("Detected this may be a dump file.");
                    Console.WriteLine("Input il2cpp dump address or input 0 to force continue:");
                    var DumpAddr = Convert.ToUInt64(Console.ReadLine(), 16);
                    if (DumpAddr != 0)
                    {
                        il2Cpp.ImageBase = DumpAddr;
                        il2Cpp.IsDumped = true;
                        if (!config.NoRedirectedPointer)
                        {
                            elf.Reload();
                        }
                    }
                }
                else
                {
                    il2Cpp.IsDumped = true;
                }
            }

            Console.WriteLine("Searching...");
            try
            {
                var flag = il2Cpp.PlusSearch(metadata.methodDefs.Count(x => x.methodIndex >= 0), metadata.typeDefs.Length, metadata.imageDefs.Length);
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    if (!flag && il2Cpp is PE)
                    {
                        Console.WriteLine("Use custom PE loader");
                        il2Cpp = PELoader.Load(il2cppPath);
                        il2Cpp.SetProperties(version, metadata.metadataUsagesCount, metadata);
                        flag = il2Cpp.PlusSearch(metadata.methodDefs.Count(x => x.methodIndex >= 0), metadata.typeDefs.Length, metadata.imageDefs.Length);
                    }
                }
                if (!flag)
                {
                    flag = il2Cpp.Search();
                }
                if (!flag)
                {
                    flag = il2Cpp.SymbolSearch();
                }
                if (!flag && il2Cpp.PointerSize == 8)
                {
                    flag = Arm64RegisterScanner.Search(il2Cpp);
                }
                if (!flag && config.EnablePointerDensityScanner)
                {
                    Console.WriteLine("Scanning pointer density & clusters in data sections...");
                    flag = PointerDensityScanner.Search(il2Cpp, metadata, config.PointerDensityThreshold);
                }
                if (!flag && config.EnableStringCrossReferencer)
                {
                    Console.WriteLine("Cross-referencing runtime strings and assertions...");
                    flag = StringCrossReferencer.Search(il2Cpp, metadata, config.PointerDensityThreshold);
                }
                if (!flag)
                {
                    // Try to use Il2CppInspectorRedux's script.json
                    var bridgeResult = Il2CppInspectorBridge.AutoDetect(il2cppPath);
                    if (bridgeResult.HasValue)
                    {
                        var (codeRegistration, metadataRegistration) = bridgeResult.Value;
                        il2Cpp.Init(codeRegistration, metadataRegistration);
                        flag = true;
                    }
                }

                if (!flag)
                {
                    Console.WriteLine("ERROR: Can't use auto mode to process file, try manual mode.");
                    Console.WriteLine("TIP: You can run Il2CppInspectorRedux first to generate script.json");
                    Console.Write("Input CodeRegistration: ");
                    var codeRegistration = Convert.ToUInt64(Console.ReadLine(), 16);
                    Console.Write("Input MetadataRegistration: ");
                    var metadataRegistration = Convert.ToUInt64(Console.ReadLine(), 16);
                    il2Cpp.Init(codeRegistration, metadataRegistration);
                }
                if (il2Cpp.Version >= 27 && il2Cpp.IsDumped)
                {
                    var typeDef = metadata.typeDefs[0];
                    var il2CppType = il2Cpp.types[typeDef.byvalTypeIndex];
                    var typeDefinitionsOffset = metadata.Version >= 38
                        ? (ulong)metadata.header.typeDefinitions.offset
                        : metadata.header.typeDefinitionsOffset;
                    metadata.ImageBase = il2CppType.data.typeHandle - typeDefinitionsOffset;
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                Console.WriteLine("ERROR: An error occurred while processing.");
                return false;
            }
            return true;
        }

        private static void Dump(Metadata metadata, Il2Cpp il2Cpp, string outputDir)
        {
            Console.WriteLine("Dumping...");
            var executor = new Il2CppExecutor(metadata, il2Cpp);
            var decompiler = new Il2CppDecompiler(executor);
            decompiler.Decompile(config, outputDir);
            Console.WriteLine("Done!");
            if (config.GenerateStruct)
            {
                Console.WriteLine("Generating struct...");
                try
                {
                    var scriptGenerator = new StructGenerator(executor);
                    scriptGenerator.WriteScript(outputDir);
                    Console.WriteLine("Done!");
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                    Console.WriteLine("ERROR: Some errors in generating struct");
                }
            }
            if (config.GenerateDummyDll)
            {
                Console.WriteLine("Generate dummy dll...");
                try
                {
                    DummyAssemblyExporter.Export(executor, outputDir, config.DummyDllAddToken);
                    Console.WriteLine("Done!");
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                    Console.WriteLine("ERROR: Some errors in generating dummy dll");
                }
            }
        }
    }
}
