# NewWorldInterface

A Windows kernel-interface tool that communicates with a companion driver via shared memory sections and kernel events. It resolves kernel symbols from `ntoskrnl.exe`'s PDB at startup and exposes an interactive command loop for VAD-tree inspection and manipulation, virtual/physical memory access, and process memory operations.

---

## Requirements

- Windows 10/11 x64
- The companion kernel driver must be loaded and its shared sections/events already created before launching this executable.
- `ntoskrnl.exe` must be present at `C:\Windows\System32\ntoskrnl.exe` (standard location).
- The matching PDB for `ntoskrnl.exe` must exist in the working directory, **or** the tool will attempt to download it from `msdl.microsoft.com`.
- The process must run with sufficient privileges to call `EnumDeviceDrivers` and open the driver's named objects.

---

## Why

Most memory-inspection tooling either runs entirely from usermode — and so
can't touch paging structures or another process's VAD tree — or hardcodes
kernel offsets that break on the next Windows build. This tool avoids both.

- **Build-agnostic by design.** At startup it parses `ntoskrnl.exe`,
  fetches the matching PDB, and resolves every required offset and RVA at
  runtime via DbgHelp. No per-build offset tables, no recompiling when
  Patch Tuesday moves a field.
- **Direct access to the structures that matter.** VAD nodes, Control
  Areas, and PTEs are first-class operations here — walk the tree, insert
  or delete nodes, relink a PTE to a chosen physical page, or map a section
  view into another process.
- **A workbench, not a one-shot.** The interactive loop is meant for
  iterative research — populate, inspect, modify, read back — rather than
  firing a single fixed action.

Intended for Windows internals research, reverse engineering, and
memory-forensics experimentation on systems you own or are authorized to test

---

## Command-line arguments

| Flag | Argument | Description |
|------|----------|-------------|
| `/s` | `<name>` | Set the **source** process name on startup (e.g. `explorer.exe`) |
| `/t` | `<name>` | Set the **target** process name on startup |
| `/i` | `<hex>`  | Initial target VPN (virtual page number), prefix `0x` accepted |
| `/o` | `<hex>`  | Offset added to `/i` (allows fine-grained page selection) |
| `/m` | `<dec>`  | Initial memory view size in pages |

Example:
```
NewWorldUserInterface.exe /s explorer.exe /t notepad.exe /i 0x7ff6a0000 /m 16
```

---

## Interactive commands

After startup the tool prints a help box and enters the command loop. Press the listed key (case-insensitive) and follow any on-screen prompts.

### Process

| Key | Command | Description |
|-----|---------|-------------|
| `I` | Set source process | Enter the name of the **source** process (the one whose memory will be read/linked from) |
| `O` | Set target process | Enter the name of the **target** process (the one whose VAD tree will be walked/modified) |

### VAD Tree

| Key | Command | Description |
|-----|---------|-------------|
| `1` | Populate | Asks the driver to walk the target process's VAD tree and populate the shared VAD buffer |
| `2` | Quick view | Prints a raw columnar dump of the VAD buffer (`GetSymOffsets` format) without building an index |
| `T` | Indexed tree view | Builds a numbered, indented tree (`ShowTree` format) and stores per-entry VPNs for use by `D` |
| `N` | Insert node | Prompts for parameters and asks the driver to insert a new VAD node into the target process |
| `D` | Delete node | Selects a node by index from the last `T` listing and asks the driver to remove it |
| `V` | Map view | Maps an existing Control Area (section object) into another process by sending a VAD-insert request with the chosen CA pointer |
| `F` | Find viewers | Finds all processes that currently share a view of a given section/Control Area |
| `4` | Link PTE | Prompts for a source virtual address and a target VPN, then asks the driver to point the target PTE at the source physical page |
| `X` | Unlink | Signals the driver's Unlink event to reverse the last PTE link |

### Memory

| Key | Command | Description |
|-----|---------|-------------|
| `Q` | Read virtual | Reads virtual memory from the source or target process and hex-dumps the result |
| `E` | Write virtual | Writes bytes to virtual memory in the target process |
| `M` | Set view size | Sets the number of pages used for the mapped-view / PTE-link operations |
| `R` | Read physical | Reads a physical address via the driver's physical-read shared buffer |
| `W` | Write physical | Writes bytes to a physical address via the driver's physical-write shared buffer |
| `P` | Pattern scan | Hex-pattern scan (wildcards `??` supported) over a chosen memory range |
| `A` | Change protection | Changes the VAD protection flags for a target region via the driver |

### Dump

| Key | Sub-option | Description |
|-----|-----------|-------------|
| `Z` | `D` | Creates a **minidump** of the target process via the driver |
| `Z` | `P` | Strips protection and handle constraints before dumping |

### Exit

| Key | Description |
|-----|-------------|
| `5` | Exit with cleanup — signals the Unlink event and closes all handles gracefully |
| `6` | Silent exit — returns immediately without any cleanup signalling |

---

## Startup sequence

1. Loads `ntoskrnl.exe` from `System32`, parses its PE headers to locate the embedded PDB path.
2. Verifies the PDB exists locally; downloads it from the Microsoft Symbol Server if missing.
3. Initialises DbgHelp (`SymInitializeW` + `SymLoadModuleExW`) and resolves all required kernel field offsets and function RVAs.
4. Opens all named shared sections and events created by the driver.
5. Writes the resolved symbol data into the `INIT`/`SYMBOL` shared section and fires the `INIT` event so the driver can begin operation.
6. Applies any `/s`, `/t`, `/i`, `/m`, `/o` command-line overrides.
7. Enters the interactive command loop.
