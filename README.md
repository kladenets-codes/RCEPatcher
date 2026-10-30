# RCE Patcher

Protects the World of Warcraft 3.3.5a client (build 12340) against the known remote code execution (RCE) vectors that a malicious private server can use to run code on your computer.

It is based on [RCEPatcher v2.0](https://github.com/bradyrussell/RCEPatcher2) by Brady Russell, with one change: it works with custom clients that load their own DLLs.

## Why this fork

RCEPatcher v2.0 patch **P4** turns the client's `LoadLibraryA` wrapper (VA `0x86C4E0`) into `return 0`, so the client cannot load any DLL through it. The goal is to block `Cache\Survey.dll`, a DLL the server can send to the client. However, some private-server clients use the same wrapper to load their own client DLL (for example `rebuffed.dll`), and with P4 those clients crash on start.

This patcher leaves the wrapper alone and removes only the one call that loads `Cache\Survey.dll` (patch **S1**). All other v2.0 patches are applied unchanged.

## Patches

| Id | File offset | Original | Patched | What it does |
|----|-------------|----------|---------|--------------|
| P0 | `0x0002A7` | `E0` | `C0` | Removes the execute flag from the `.zdata` section (the original RCEPatcher fix) |
| P1 | `0x14A842` | `3B 3D B0 A5 BE 00` | `83 FF 50 90 90 90` | Bounds check (VA `0x54B442`) |
| P2 | `0x14A85C` | `83 F8 02 7D 1F` | `83 F8 50 7F 5F` | Bounds check (VA `0x54B45C`) |
| P3 | `0x364D40` | `74` | `EB` | Forced branch (VA `0x765940`) |
| P5 | `0x0614A0` | `55 8B EC` | `33 C0 C3` | Disabled function (VA `0x4620A0`) |
| P6 | `0x46AC43` | `76 0C` | `90 90` | Length check (VA `0x86B843`) |
| S1 | `0x0E405A` | `E8 81 78 38 00` | `33 C0 90 90 90` | `call LoadLibrary("Cache\Survey.dll")` replaced by `xor eax, eax`; the client takes its own "DLL not loaded" path (VA `0x4E4C5A`) |

Upstream P4 is intentionally **not** applied. Upstream has not published what P1-P3, P5 and P6 fix; the descriptions above only state what the bytes do.

## Usage

1. Download `RCEPatcher.exe` from [Releases](../../releases).
2. Drag and drop your `Wow.exe` onto `RCEPatcher.exe`.
3. A patched copy `Wow_RCE_fix2.exe` is created next to it. Your original `Wow.exe` is not modified.
4. Start the game with `Wow_RCE_fix2.exe`.

Command line:

```
RCEPatcher.exe <path\to\Wow.exe> [--check] [--no-pause]
```

- `--check` only prints the state of every patch. Exit code 0 means all patches are applied.
- `--no-pause` does not wait for a key press at the end (for scripts).

The patcher only accepts build 12340 (PE timestamp `0x4C2452FE`). It checks the original bytes at every location first and writes nothing if any location contains unexpected bytes. After writing, it reads the new file back and verifies each patch.

Requirements: Windows 10 or 11 (.NET Framework 4.8, preinstalled).

## Building

```
dotnet build src/RCEPatcher -c Release
```

The exe is written to `src/RCEPatcher/bin/Release/net48/RCEPatcher.exe`.

## Notes

- There are very likely more attack vectors in build 12340. The safest option is still to avoid untrusted servers.
- Some servers or launchers check the client executable and may reject or replace a modified copy.

## Credits

- [stoneharry](https://github.com/stoneharry): original RCEPatcher (`.zdata` fix).
- [Brady Russell](https://github.com/bradyrussell): RCEPatcher v2.0 research and patches P0-P6.

## License

MIT for the code in this repository. See [LICENSE](LICENSE).
