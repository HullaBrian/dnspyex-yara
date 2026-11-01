using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace dnSpy.Yara.Core {
	public sealed class YaraOptions {
		/// <summary>Replace the row bytes of metadata tokens (call/ldfld/newobj/ldstr/...) with <c>??</c>, keeping the
		/// table byte. Tokens change whenever the assembly is rebuilt, so this makes rules survive recompilation.</summary>
		public bool WildcardTokens { get; set; } = true;
		/// <summary>Replace branch / switch displacements with <c>??</c>.</summary>
		public bool WildcardBranches { get; set; }
		/// <summary>When building a full rule, add the <c>ldstr</c> literals of the selection as extra strings.</summary>
		public bool IncludeStrings { get; set; } = true;
		public string Author { get; set; } = string.Empty;
		public DateTime Now { get; set; } = DateTime.Now;
	}

	/// <summary>Turns IL ranges into YARA hex strings (with the IL as comments) or complete rules.</summary>
	public sealed class YaraGenerator {
		const string Indent = "    ";
		const int BytesPerLine = 16;
		const int MinStringLiteralLength = 4;
		const int MaxStringLiteralLength = 256;

		readonly YaraOptions options;

		public YaraGenerator(YaraOptions options) => this.options = options ?? throw new ArgumentNullException(nameof(options));

		/// <summary>Just the <c>$il_N = { ... }</c> definitions, ready to paste into a rule's <c>strings:</c> section.</summary>
		public string GenerateStrings(IReadOnlyList<IlRange> ranges) {
			var sb = new StringBuilder();
			AppendHexStrings(sb, ranges, string.Empty);
			return sb.ToString();
		}

		public string GenerateRule(IReadOnlyList<IlRange> ranges) {
			if (ranges.Count == 0)
				throw new ArgumentException("No IL selected", nameof(ranges));
			var methods = ranges.Select(r => r.Method).Distinct().ToList();
			var modules = methods.Select(m => m.Module).Where(m => m is not null).Distinct().ToList();
			var i2 = Indent + Indent;

			var sb = new StringBuilder();
			sb.Append("rule ").Append(RuleName(methods)).Append('\n');
			sb.Append("{\n");
			sb.Append(Indent).Append("meta:\n");
			Meta(sb, "description", methods.Count == 1
				? "IL pattern from " + MethodName(methods[0])
				: $"IL patterns from {methods.Count} methods");
			Meta(sb, "author", options.Author);
			Meta(sb, "date", options.Now.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture));
			Meta(sb, "generator", "dnSpy.Yara");
			foreach (var mod in modules) {
				Meta(sb, "module", mod!.Name);
				if (mod.Mvid is Guid mvid)
					Meta(sb, "mvid", mvid.ToString("D"));
				if (TrySha256(mod.Location) is string hash)
					Meta(sb, "sha256", hash);
			}
			for (int i = 0; i < methods.Count; i++)
				Meta(sb, methods.Count == 1 ? "method" : "method_" + i.ToString(CultureInfo.InvariantCulture), MethodName(methods[i]));
			Meta(sb, "wildcards", Wildcards());

			sb.Append('\n').Append(Indent).Append("strings:\n");
			var splits = AppendHexStrings(sb, ranges, i2);

			if (options.IncludeStrings) {
				var literals = ranges.SelectMany(r => r.Instructions)
					.Where(i => i.OpCode.Code == Code.Ldstr && i.Operand is string s && s.Length >= MinStringLiteralLength)
					.Select(i => (string)i.Operand)
					.Distinct(StringComparer.Ordinal)
					.ToList();
				if (literals.Count > 0) {
					sb.Append('\n').Append(i2).Append("// ldstr literals (stored as UTF-16 in the #US heap)\n");
					for (int i = 0; i < literals.Count; i++)
						sb.Append(i2).Append("$str_").Append(i).Append(" = ").Append(StringLiteral(literals[i])).Append('\n');
				}
			}

			sb.Append('\n').Append(Indent).Append("condition:\n");
			sb.Append(i2).Append("uint16(0) == 0x5A4D and all of them");
			foreach (var split in splits)
				sb.Append(" and\n").Append(i2).Append(AdjacencyCondition(split));
			sb.Append('\n');
			sb.Append("}\n");
			return sb.ToString();
		}

		string Wildcards() {
			var parts = new List<string>();
			if (options.WildcardTokens) parts.Add("metadata tokens");
			if (options.WildcardBranches) parts.Add("branch offsets");
			return parts.Count == 0 ? "none" : string.Join(", ", parts);
		}

		/// <summary>
		/// YARA silently stops matching hex strings that contain wildcards once they extend more than ~1KB from
		/// their atom (literal strings are unaffected). Longer wildcarded patterns are therefore split, on instruction
		/// boundaries, into chunks of at most this many bytes that the condition requires to be adjacent.
		/// </summary>
		public const int MaxWildcardChunkBytes = 1000;

		/// <summary>A hex string that was split; <see cref="Offsets"/>[k] is chunk k's offset from chunk 0.</summary>
		sealed class SplitString {
			public List<string> Names { get; } = new List<string>();
			public List<int> Offsets { get; } = new List<int>();
		}

		List<SplitString> AppendHexStrings(StringBuilder sb, IReadOnlyList<IlRange> ranges, string indent) {
			var splits = new List<SplitString>();
			for (int r = 0; r < ranges.Count; r++) {
				var range = ranges[r];
				if (r > 0)
					sb.Append('\n');
				var instrs = IlBytes.Read(range, out var source);
				var perInstr = instrs.Select(ib => (ib, tokens: HexTokens(ib))).ToList();
				int byteCount = perInstr.Sum(x => x.tokens.Length);
				bool hasWildcards = perInstr.Any(x => x.tokens.Contains("??"));

				var chunks = new List<List<(InstructionBytes ib, string[] tokens)>> { new List<(InstructionBytes, string[])>() };
				int chunkBytes = 0;
				foreach (var x in perInstr) {
					if (hasWildcards && chunkBytes > 0 && chunkBytes + x.tokens.Length > MaxWildcardChunkBytes) {
						chunks.Add(new List<(InstructionBytes, string[])>());
						chunkBytes = 0;
					}
					chunks[^1].Add(x);
					chunkBytes += x.tokens.Length;
				}

				sb.Append(indent).Append("// ").Append(OneLine(MethodName(range.Method))).Append('\n');
				sb.Append(indent).Append("// ").Append(InstructionText.Label(range.StartOffset)).Append(" - ")
					.Append(InstructionText.Label(instrs.Count == 0 ? 0 : instrs[^1].Instruction.Offset))
					.Append($" ({instrs.Count} instruction{(instrs.Count == 1 ? "" : "s")}, {byteCount} byte{(byteCount == 1 ? "" : "s")}")
					.Append(source switch {
						IlBytesSource.File => ")",
						IlBytesSource.ReEncodedModified => ", re-encoded: body differs from file, was it edited?)",
						_ => ", re-encoded: original file bytes unavailable)",
					})
					.Append('\n');

				SplitString? split = null;
				if (chunks.Count > 1) {
					split = new SplitString();
					int off = 0;
					for (int k = 0; k < chunks.Count; k++) {
						split.Names.Add($"il_{r}_{k}");
						split.Offsets.Add(off);
						off += chunks[k].Sum(x => x.tokens.Length);
					}
					splits.Add(split);
					sb.Append(indent).Append("// split into ").Append(chunks.Count)
						.Append(" adjacent parts: YARA can't match wildcarded hex strings longer than ~1KB. Require adjacency with:\n");
					sb.Append(indent).Append("//   ").Append(AdjacencyCondition(split)).Append('\n');
				}

				for (int k = 0; k < chunks.Count; k++) {
					var chunk = chunks[k];
					var rows = new List<(string hex, string? comment)>();
					foreach (var (ib, tokens) in chunk) {
						var comment = InstructionText.Format(ib.Instruction);
						for (int i = 0; i < tokens.Length; i += BytesPerLine)
							rows.Add((string.Join(" ", tokens.Skip(i).Take(BytesPerLine)), i == 0 ? comment : null));
					}
					int width = rows.Count == 0 ? 0 : rows.Max(x => x.hex.Length);
					int fixedRun = LongestFixedRun(chunk.SelectMany(x => x.tokens));
					if (fixedRun < 4)
						sb.Append(indent).Append("// note: longest run of fixed bytes is ").Append(fixedRun)
							.Append(", YARA may flag this string as slow. Select more code or disable wildcards.\n");

					sb.Append(indent).Append('$').Append(split is null ? $"il_{r}" : split.Names[k]).Append(" = {\n");
					foreach (var (hex, comment) in rows) {
						sb.Append(indent).Append(Indent).Append(hex);
						if (comment is not null)
							sb.Append(' ', width - hex.Length + 2).Append("// ").Append(comment);
						sb.Append('\n');
					}
					sb.Append(indent).Append("}\n");
				}
			}
			return splits;
		}

		/// <summary>Anchors every part to the same occurrence of part 0 (part 0 may match in several places).</summary>
		static string AdjacencyCondition(SplitString s) {
			var first = s.Names[0];
			var parts = Enumerable.Range(1, s.Names.Count - 1)
				.Select(k => $"${s.Names[k]} at @{first}[i] + {s.Offsets[k]}");
			return $"for any i in (1..#{first}) : ({string.Join(" and ", parts)})";
		}

		string[] HexTokens(InstructionBytes ib) {
			var b = ib.Bytes;
			var wild = new bool[b.Length];
			int p = ib.OpCodeSize;
			void Mask(int from, int count) {
				for (int i = from; i < from + count && i < wild.Length; i++)
					wild[i] = true;
			}
			switch (ib.Instruction.OpCode.OperandType) {
			case OperandType.InlineField:
			case OperandType.InlineMethod:
			case OperandType.InlineTok:
			case OperandType.InlineType:
			case OperandType.InlineSig:
			case OperandType.InlineString:
				// Token = 3-byte row/heap offset (little endian) + 1-byte table. Keep the table byte: it pins down
				// what *kind* of thing is referenced (0x0A MemberRef, 0x06 MethodDef, 0x70 string, ...).
				if (options.WildcardTokens)
					Mask(p, 3);
				break;
			case OperandType.InlineBrTarget:
				if (options.WildcardBranches) Mask(p, 4);
				break;
			case OperandType.ShortInlineBrTarget:
				if (options.WildcardBranches) Mask(p, 1);
				break;
			case OperandType.InlineSwitch:
				if (options.WildcardBranches) Mask(p + 4, b.Length - p - 4); // keep the target count
				break;
			}
			var tokens = new string[b.Length];
			for (int i = 0; i < b.Length; i++)
				tokens[i] = b[i] < 0 || wild[i] ? "??" : b[i].ToString("X2");
			return tokens;
		}

		static int LongestFixedRun(IEnumerable<string> tokens) {
			int best = 0, cur = 0;
			foreach (var t in tokens) {
				cur = t == "??" ? 0 : cur + 1;
				best = Math.Max(best, cur);
			}
			return best;
		}

		static string StringLiteral(string s) {
			if (s.Length > MaxStringLiteralLength)
				s = s.Substring(0, MaxStringLiteralLength);
			// Plain printable ASCII can use a text string with the 'wide' modifier; anything else is emitted as the
			// exact UTF-16LE bytes, since 'wide' only zero-extends single bytes.
			if (s.All(c => (c >= 0x20 && c < 0x7F) || c == '\t' || c == '\n' || c == '\r'))
				return "\"" + EscapeText(s) + "\" wide";
			var bytes = Encoding.Unicode.GetBytes(s);
			return "{ " + string.Join(" ", bytes.Select(x => x.ToString("X2"))) + " }";
		}

		static string EscapeText(string s) {
			var sb = new StringBuilder(s.Length);
			Span<byte> utf8 = stackalloc byte[4];
			foreach (var rune in s.EnumerateRunes()) {
				int c = rune.Value;
				switch (c) {
				case '"': sb.Append("\\\""); break;
				case '\\': sb.Append("\\\\"); break;
				case '\n': sb.Append("\\n"); break;
				case '\r': sb.Append("\\r"); break;
				case '\t': sb.Append("\\t"); break;
				default:
					if (c < 0x20 || c >= 0x7F) {
						// YARA text strings are byte strings: emit non-ASCII as its UTF-8 bytes
						int n = rune.EncodeToUtf8(utf8);
						for (int i = 0; i < n; i++)
							sb.Append("\\x").Append(utf8[i].ToString("X2"));
					}
					else
						sb.Append((char)c);
					break;
				}
			}
			return sb.ToString();
		}

		void Meta(StringBuilder sb, string key, string? value) =>
			sb.Append(Indent).Append(Indent).Append(key).Append(" = \"").Append(EscapeText(value ?? string.Empty)).Append("\"\n");

		static string MethodName(MethodDef m) => m.FullName;

		static string OneLine(string s) => s.Replace('\r', ' ').Replace('\n', ' ');

		static string RuleName(List<MethodDef> methods) {
			string raw;
			if (methods.Count == 1) {
				var m = methods[0];
				raw = $"{m.DeclaringType?.Name}_{m.Name}";
			}
			else {
				var types = methods.Select(m => m.DeclaringType).Distinct().ToList();
				raw = types.Count == 1 ? $"{types[0]?.Name}_{methods.Count}_methods" : (methods[0].Module?.Name ?? "dotnet") + "_il";
			}
			var sb = new StringBuilder("dotnet_");
			foreach (var c in raw)
				sb.Append(c < 0x80 && (char.IsLetterOrDigit(c) || c == '_') ? c : '_');
			var name = sb.ToString();
			while (name.Contains("__"))
				name = name.Replace("__", "_");
			name = name.TrimEnd('_');
			return name.Length > 128 ? name.Substring(0, 128) : name;
		}

		static string? TrySha256(string? path) {
			try {
				if (string.IsNullOrEmpty(path) || !File.Exists(path))
					return null;
				using var fs = File.OpenRead(path);
				return Convert.ToHexString(SHA256.HashData(fs)).ToLowerInvariant();
			}
			catch {
				return null;
			}
		}
	}
}
