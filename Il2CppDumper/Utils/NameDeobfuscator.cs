using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace Il2CppDumper
{
    public static class NameDeobfuscator
    {
        private static readonly Regex ValidAsciiIdentRegex = new(@"^[a-zA-Z_<>$][a-zA-Z0-9_<>$`]*$", RegexOptions.Compiled);

        /// <summary>
        /// Returns true if a name is heavily obfuscated (contains non-ASCII, unprintable, or surrogate characters).
        /// </summary>
        public static bool IsObfuscated(string name)
        {
            if (string.IsNullOrEmpty(name)) return true;
            if (!ValidAsciiIdentRegex.IsMatch(name)) return true;

            // Check if contains high unicode characters (e.g. CJK, Arabic, Cyrillic homoglyphs)
            foreach (char c in name)
            {
                if (c > 127) return true;
                if (char.IsControl(c)) return true;
            }

            return false;
        }

        /// <summary>
        /// Normalizes an obfuscated type name to a clean identifier.
        /// </summary>
        public static string NormalizeTypeName(string rawName, int typeDefIndex)
        {
            if (!IsObfuscated(rawName)) return rawName;
            return $"Type_{typeDefIndex}";
        }

        /// <summary>
        /// Normalizes an obfuscated method name using its RVA address or index.
        /// </summary>
        public static string NormalizeMethodName(string rawName, ulong rva, int methodIndex)
        {
            if (rawName == ".ctor" || rawName == ".cctor") return rawName;
            if (!IsObfuscated(rawName)) return rawName;
            if (rva > 0) return $"Method_{rva:X}";
            return $"Method_idx_{methodIndex}";
        }

        /// <summary>
        /// Normalizes an obfuscated field name using its offset or index.
        /// </summary>
        public static string NormalizeFieldName(string rawName, int offset, int fieldIndex)
        {
            if (!IsObfuscated(rawName)) return rawName;
            if (offset >= 0) return $"Field_0x{offset:X}";
            return $"Field_idx_{fieldIndex}";
        }

        /// <summary>
        /// Normalizes an obfuscated property name.
        /// </summary>
        public static string NormalizePropertyName(string rawName, int propIndex)
        {
            if (!IsObfuscated(rawName)) return rawName;
            return $"Property_{propIndex}";
        }

        /// <summary>
        /// Normalizes an obfuscated parameter name.
        /// </summary>
        public static string NormalizeParameterName(string rawName, int paramIndex)
        {
            if (!IsObfuscated(rawName)) return rawName;
            return $"p_{paramIndex}";
        }
    }
}
