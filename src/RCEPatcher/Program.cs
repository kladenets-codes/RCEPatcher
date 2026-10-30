using System;
using System.IO;
using System.Linq;

namespace RCEPatcher
{
    internal sealed class Patch
    {
        public readonly string Id;
        public readonly string Note;
        public readonly long Offset;
        public readonly byte[] Original;
        public readonly byte[] Patched;

        public Patch(string id, string note, long offset, string original, string patched)
        {
            Id = id;
            Note = note;
            Offset = offset;
            Original = Hex(original);
            Patched = Hex(patched);
        }

        private static byte[] Hex(string s)
        {
            s = s.Replace(" ", "");
            return Enumerable.Range(0, s.Length / 2).Select(i => Convert.ToByte(s.Substring(i * 2, 2), 16)).ToArray();
        }
    }

    internal static class Program
    {
        private const uint Timestamp12340 = 0x4C2452FE;

        // File offsets in Wow.exe build 12340. P0-P6 (minus P4) come from RCEPatcher v2.0 by bradyrussell.
        private static readonly Patch[] Patches =
        {
            new Patch("P0", ".zdata section: remove execute flag", 0x0002A7, "E0", "C0"),
            new Patch("P1", "bounds check (VA 0x54B442)", 0x14A842, "3B 3D B0 A5 BE 00", "83 FF 50 90 90 90"),
            new Patch("P2", "bounds check (VA 0x54B45C)", 0x14A85C, "83 F8 02 7D 1F", "83 F8 50 7F 5F"),
            new Patch("P3", "branch forced (VA 0x765940)", 0x364D40, "74", "EB"),
            new Patch("P5", "function disabled (VA 0x4620A0)", 0x0614A0, "55 8B EC", "33 C0 C3"),
            new Patch("P6", "length check (VA 0x86B843)", 0x46AC43, "76 0C", "90 90"),
            // Replaces upstream P4, which made the client's LoadLibraryA wrapper (VA 0x86C4E0) always fail.
            // That also blocked DLLs that custom clients load on purpose and crashed them.
            // Here only the call that loads the server-supplied Cache\Survey.dll is removed.
            new Patch("S1", "Survey.dll load disabled (VA 0x4E4C5A)", 0x0E405A, "E8 81 78 38 00", "33 C0 90 90 90"),
        };

        private enum State { Original, Patched, Unexpected }

        private static int Main(string[] args)
        {
            Console.WriteLine("RCE Patcher - WoW 3.3.5a (build 12340)");
            Console.WriteLine();
            bool checkOnly = args.Contains("--check");
            bool noPause = args.Contains("--no-pause");
            string path = args.FirstOrDefault(a => !a.StartsWith("--"));
            int code;
            try
            {
                code = path == null ? Usage() : Run(path, checkOnly);
            }
            catch (Exception e)
            {
                Console.WriteLine("[ERROR] " + e.Message);
                code = 1;
            }
            if (!noPause)
            {
                Console.WriteLine("Press any key to exit.");
                try { Console.ReadKey(true); } catch (InvalidOperationException) { }
            }
            return code;
        }

        private static int Usage()
        {
            Console.WriteLine("Drag and drop Wow.exe onto RCEPatcher.exe, or run:");
            Console.WriteLine("  RCEPatcher.exe <path\\to\\Wow.exe> [--check] [--no-pause]");
            return 1;
        }

        private static int Run(string path, bool checkOnly)
        {
            if (!File.Exists(path)) { Console.WriteLine("[ERROR] File not found: " + path); return 1; }
            byte[] data = File.ReadAllBytes(path);
            if (!IsBuild12340(data)) { Console.WriteLine("[ERROR] Not a WoW 3.3.5a build 12340 executable."); return 1; }

            State[] states = Patches.Select(p => StateOf(data, p)).ToArray();
            Print(states);
            if (checkOnly) return states.All(s => s == State.Patched) ? 0 : 2;

            if (states.Contains(State.Unexpected))
            {
                Console.WriteLine("[ERROR] Unexpected bytes at a patch location. Nothing was written.");
                return 1;
            }
            if (states.All(s => s == State.Patched))
            {
                Console.WriteLine("[OK] All patches are already applied.");
                return 0;
            }

            string output = Path.Combine(Path.GetDirectoryName(Path.GetFullPath(path)),
                Path.GetFileNameWithoutExtension(path) + "_RCE_fix2.exe");
            if (File.Exists(output)) { Console.WriteLine("[ERROR] Output already exists: " + output); return 1; }

            foreach (Patch p in Patches) Array.Copy(p.Patched, 0, data, p.Offset, p.Patched.Length);
            File.WriteAllBytes(output, data);

            byte[] written = File.ReadAllBytes(output);
            if (!Patches.All(p => StateOf(written, p) == State.Patched))
            {
                File.Delete(output);
                Console.WriteLine("[ERROR] Verification failed, output deleted.");
                return 1;
            }
            Console.WriteLine("[OK] Created " + output + ". Your original file was not modified.");
            return 0;
        }

        private static bool IsBuild12340(byte[] d)
        {
            if (d.Length < 0x400 || d[0] != 'M' || d[1] != 'Z') return false;
            int pe = BitConverter.ToInt32(d, 0x3C);
            if (pe <= 0 || pe + 8 > d.Length || BitConverter.ToUInt32(d, pe) != 0x00004550) return false;
            return BitConverter.ToUInt32(d, pe + 8) == Timestamp12340;
        }

        private static State StateOf(byte[] d, Patch p)
        {
            if (p.Offset + p.Original.Length > d.Length) return State.Unexpected;
            byte[] cur = d.Skip((int)p.Offset).Take(p.Original.Length).ToArray();
            if (cur.SequenceEqual(p.Original)) return State.Original;
            if (cur.SequenceEqual(p.Patched)) return State.Patched;
            return State.Unexpected;
        }

        private static void Print(State[] states)
        {
            for (int i = 0; i < Patches.Length; i++)
            {
                string s = states[i] == State.Original ? "not applied" : states[i] == State.Patched ? "applied" : "UNEXPECTED";
                Console.WriteLine($"  {Patches[i].Id,-3} 0x{Patches[i].Offset:X6}  {Patches[i].Note,-42} {s}");
            }
            Console.WriteLine();
        }
    }
}
