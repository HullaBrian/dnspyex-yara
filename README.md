# dnSpy.Yara

A dnSpyEx extension for turning .NET code into YARA rules. Highlight code, right-click, choose **YARA → Copy YARA Hex String**, and you get the selection's IL bytes as a YARA hex string. Each instruction sits on its own line with the IL as a comment:

```yara
// System.String Sample.Loader.Program::Dispatch(System.Int32)
// IL_002E - IL_0039 (4 instructions, 12 bytes)
$il_0 = {
    72 ?? ?? ?? 70  // IL_002E: ldstr "download"
    2A              // IL_0033: ret
    72 ?? ?? ?? 70  // IL_0034: ldstr "upload"
    2A              // IL_0039: ret
}
```

**Copy YARA Rule** wraps the same strings in a complete rule. The rule's metadata holds the module name, MVID, SHA-256 and method names. The `ldstr` literals become extra `wide` strings, and the condition starts with an MZ check.

## Where it works

| Where | What gets copied |
|---|---|
| C# / VB view, text selected | IL of every statement the selection touches (lambdas/local functions become separate strings) |
| IL view, lines selected | Exactly the selected instructions |
| Caret on a method's name, no selection | The whole method body |
| Caret inside a method, no selection | The statement under the caret |
| Assembly Explorer, one or more methods selected | Whole method bodies, one string per method |

Shortcuts in the code view: **Ctrl+Alt+Y** copies the hex string, **Ctrl+Alt+Shift+Y** copies the rule.

## Options (YARA submenu, saved between sessions)

- **Wildcard Metadata Tokens** (on by default). The row bytes of `call`/`newobj`/`ldfld`/`ldstr`/... tokens become `??`. The table byte is kept (`28 ?? ?? ?? 0A` = call to a MemberRef), because tokens change whenever the assembly is rebuilt.
- **Wildcard Branch Offsets**. Branch and `switch` displacements become `??`.
- **Add ldstr Literals to Rule** (on by default). Printable ASCII literals become `"..." wide`. Anything else is written as its exact UTF-16LE bytes.

The rule's `author` meta comes from the `Author` attribute of the dnSpy.Yara section in dnSpy's settings XML.

## How the bytes are produced

- Bytes are read from the **PE image on disk** (method RVA + header), so the strings match the file exactly.
- The plugin also re-encodes each instruction from dnlib's object model and compares. If the body was **edited in dnSpy** (or no file bytes exist), it uses the re-encoded bytes, writes `??` for anything it can't know (such as a new string's `#US` offset), and says so in the header comment.
- YARA quietly stops matching hex strings that contain wildcards once they extend more than about 1 KB from their atom. Exact-byte strings aren't affected. So long wildcarded selections are split, on instruction boundaries, into `$il_N_0`, `$il_N_1`, ... parts of at most 1000 bytes. The rule's condition then requires the parts to be adjacent: `for any i in (1..#il_0_0) : ($il_0_1 at @il_0_0[i] + 996 and ...)`.
- A string whose longest run of fixed bytes is under 4 gets a `// note:` warning, because YARA will flag it as slow.

## Install from a release

1. Download `dnSpy.Yara-vX.Y.Z.zip` from the [Releases](https://github.com/HullaBrian/dnspyex-yara/releases) page.
2. Extract it into `<dnSpy>\bin\Extensions\`, so you end up with `<dnSpy>\bin\Extensions\dnSpy.Yara\dnSpy.Yara.x.dll`.
3. If Windows blocked the download, right-click the zip → Properties → **Unblock** before extracting.
4. Restart dnSpy.

Requires the **.NET build** of dnSpyEx 6.5+ (not the .NET Framework build).

## Build / install from source

Requires the .NET 10 SDK and the **.NET build** of dnSpyEx (not the .NET Framework build).

```powershell
.\scripts\install.ps1 -DnSpyDir "C:\Tools\dnSpy"    # builds against that dnSpy and copies to bin\Extensions\dnSpy.Yara
```

Then restart dnSpy. To install by hand, copy `dnSpy.Yara.x.dll` into `<dnSpy>\bin\Extensions\dnSpy.Yara\`.

## Tests

```powershell
pip install yara-python
.\tests\run-tests.ps1
```

This generates rules for every method in a sample assembly and in dnlib.dll, dnSpy.Contracts.DnSpy.dll and dnSpy.dll (up to 4000 methods each). Each method is covered as a whole body and as a partial range, with three wildcard settings, in both rule and strings-only form. One extra case uses a method body edited and saved through dnlib. yara-python compiles every rule and checks that it matches its source file (about 37,000 rules).

## Layout

```
src/dnSpy.Yara/
  Core/                  dnlib-only logic (also compiled into the test harness)
    IlRange.cs           selected IL ranges, merging per method
    IlBytes.cs           file-byte reader + re-encoder + edited-body detection
    InstructionText.cs   one-line IL formatting for comments
    YaraGenerator.cs     hex strings, wildcarding, chunking, rule assembly
  YaraSelection.cs       dnSpy selection/caret/tree nodes -> IL ranges
  YaraCommands.cs        context-menu submenu, option toggles, keyboard shortcuts, clipboard
  YaraSettings.cs        persisted options
tests/                   sample assembly, generator harness, yara-python verifier
```
