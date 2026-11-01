using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnSpy.Yara.Core;

// Usage: YaraGen.Tests <outDir> <assembly> [<assembly> ...] [--max N]
// For every method body it generates YARA output under several option combinations (whole method + a partial
// range), writes one .yar file per combination and a manifest.json that verify.py uses to compile and scan.
static class Program {
	static int Main(string[] args) {
		int max = 2500;
		var files = new List<string>();
		string? outDir = null;
		for (int i = 0; i < args.Length; i++) {
			if (args[i] == "--max") max = int.Parse(args[++i]);
			else if (outDir is null) outDir = args[i];
			else files.Add(Path.GetFullPath(args[i]));
		}
		if (outDir is null || files.Count == 0) {
			Console.Error.WriteLine("usage: YaraGen.Tests <outDir> <assembly>... [--max N]");
			return 2;
		}
		Directory.CreateDirectory(outDir);
		var manifest = new List<object>();
		int failures = 0;

		foreach (var file in files) {
			var mod = ModuleDefMD.Load(file);
			var methods = mod.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody && m.Body.Instructions.Count > 0).Take(max).ToList();
			var stem = Path.GetFileNameWithoutExtension(file);
			var reEncoded = methods.Where(m => { IlBytes.Read(IlRange.WholeMethod(m)!, out var s); return s != IlBytesSource.File; }).ToList();

			foreach (var (tag, opts) in Combos()) {
				var gen = new YaraGenerator(opts);
				var rules = new StringBuilder();
				var names = new List<string>();
				int idx = 0;
				foreach (var m in methods) {
					foreach (var range in RangesFor(IlRange.WholeMethod(m)!)) {
						string name = $"r{idx++}";
						// Alternate between the full-rule and strings-only outputs so both get compiled.
						string text = idx % 2 == 0
							? Rename(gen.GenerateRule(new[] { range }), name)
							: $"rule {name}\n{{\n    strings:\n{Indent(gen.GenerateStrings(new[] { range }), "        ")}\n    condition:\n        all of them\n}}\n";
						rules.Append(text).Append('\n');
						names.Add(name);
					}
				}
				var yar = Path.Combine(outDir, $"{stem}.{tag}.yar");
				File.WriteAllText(yar, rules.ToString());
				manifest.Add(new { target = file, rules = Path.GetFullPath(yar), expected = names });
			}
			Console.WriteLine($"{stem}: {methods.Count} methods, {reEncoded.Count} not read from file bytes");
			foreach (var m in reEncoded.Take(10))
				Console.WriteLine($"  re-encoded: {m.FullName}");
		}

		failures += ModifiedBodyTest(files[0], outDir, manifest);
		File.WriteAllText(Path.Combine(outDir, "manifest.json"), JsonSerializer.Serialize(manifest, new JsonSerializerOptions { WriteIndented = true }));
		File.WriteAllText(Path.Combine(outDir, "example.yar"), Example(files[0]));
		return failures == 0 ? 0 : 1;
	}

	static IEnumerable<(string, YaraOptions)> Combos() {
		var now = new DateTime(2026, 11, 1);
		yield return ("exact", new YaraOptions { WildcardTokens = false, WildcardBranches = false, Now = now });
		yield return ("tokens", new YaraOptions { WildcardTokens = true, WildcardBranches = false, Now = now });
		yield return ("tokens_branches", new YaraOptions { WildcardTokens = true, WildcardBranches = true, Now = now });
	}

	// Whole method, plus a range from the middle (simulates a selection that doesn't start at IL_0000).
	static IEnumerable<IlRange> RangesFor(IlRange whole) {
		yield return whole;
		var ins = whole.Instructions;
		if (ins.Count >= 6) {
			int a = ins.Count / 3, b = 2 * ins.Count / 3;
			yield return new IlRange(whole.Method, ins.Skip(a).Take(b - a + 1).ToArray());
		}
	}

	static string Rename(string rule, string name) => Regex.Replace(rule, @"^rule \S+", "rule " + name, RegexOptions.Multiline);
	static string Indent(string s, string ind) => string.Join("\n", s.TrimEnd('\n').Split('\n').Select(l => l.Length == 0 ? l : ind + l));

	/// <summary>
	/// Edit a method body (as the dnSpy IL editor would), save the module, and check the generator notices the file
	/// bytes are stale and re-encodes. verify.py then checks the re-encoded rule matches the saved file.
	/// </summary>
	static int ModifiedBodyTest(string file, string outDir, List<object> manifest) {
		var mod = ModuleDefMD.Load(file);
		var m = mod.GetTypes().SelectMany(t => t.Methods).First(x => x.Name == "Dispatch");
		var body = m.Body;
		body.Instructions.Insert(0, OpCodes.Nop.ToInstruction());
		body.Instructions.Insert(1, OpCodes.Ldstr.ToInstruction("injected-by-test"));
		body.Instructions.Insert(2, OpCodes.Pop.ToInstruction());
		body.UpdateInstructionOffsets();
		var range = IlRange.WholeMethod(m)!;
		IlBytes.Read(range, out var src);
		int fail = 0;
		if (src != IlBytesSource.ReEncodedModified) {
			Console.Error.WriteLine($"FAIL modified body: expected ReEncodedModified, got {src}");
			fail++;
		}
		var opts = new YaraOptions { WildcardTokens = false };
		var rule = Rename(new YaraGenerator(opts).GenerateRule(new[] { range }), "modified_dispatch");
		var saved = Path.GetFullPath(Path.Combine(outDir, "Sample.modified.dll"));
		mod.Write(saved);
		var yar = Path.GetFullPath(Path.Combine(outDir, "modified.yar"));
		File.WriteAllText(yar, rule);
		manifest.Add(new { target = saved, rules = yar, expected = new[] { "modified_dispatch" } });
		Console.WriteLine($"modified body: source={src}");
		return fail;
	}

	static string Example(string file) {
		var mod = ModuleDefMD.Load(file);
		var ms = mod.GetTypes().SelectMany(t => t.Methods).Where(x => x.Name == "Dispatch" || x.Name == "Unicode").Select(x => IlRange.WholeMethod(x)!).ToArray();
		var gen = new YaraGenerator(new YaraOptions { Now = new DateTime(2026, 11, 1) });
		return gen.GenerateStrings(new[] { ms[0] }) + "\n\n" + gen.GenerateRule(ms);
	}
}
