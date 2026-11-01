using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace dnSpy.Yara.Core {
	/// <summary>Formats an instruction as a single line of IL suitable for a YARA <c>//</c> comment.</summary>
	public static class InstructionText {
		const int MaxStringChars = 80;
		const int MaxOperandChars = 160;

		public static string Format(Instruction instr) {
			var sb = new StringBuilder();
			sb.Append(Label(instr.Offset)).Append(": ").Append(instr.OpCode.Name);
			var operand = FormatOperand(instr);
			if (!string.IsNullOrEmpty(operand)) {
				if (operand.Length > MaxOperandChars)
					operand = operand.Substring(0, MaxOperandChars) + "...";
				sb.Append(' ').Append(operand);
			}
			return OneLine(sb.ToString());
		}

		public static string Label(uint offset) => "IL_" + offset.ToString("X4");

		static string FormatOperand(Instruction instr) {
			switch (instr.Operand) {
			case null:
				return string.Empty;
			case Instruction target:
				return Label(target.Offset);
			case IList<Instruction> targets:
				return "(" + string.Join(", ", targets.Select(t => t is null ? "null" : Label(t.Offset))) + ")";
			case string s:
				return QuoteString(s);
			case Local local:
				return string.IsNullOrEmpty(local.Name) ? "V_" + local.Index.ToString(CultureInfo.InvariantCulture) : local.Name;
			case Parameter p:
				if (p.IsHiddenThisParameter)
					return "this";
				return string.IsNullOrEmpty(p.Name) ? "A_" + p.Index.ToString(CultureInfo.InvariantCulture) : p.Name;
			case IMethod m:
				return m.FullName;
			case IField f:
				return f.FullName;
			case ITypeDefOrRef t:
				return t.FullName;
			case MethodSig sig:
				return sig.ToString();
			case float f4:
				return f4.ToString("R", CultureInfo.InvariantCulture);
			case double f8:
				return f8.ToString("R", CultureInfo.InvariantCulture);
			case System.IFormattable fmt:
				return fmt.ToString(null, CultureInfo.InvariantCulture);
			default:
				return instr.Operand.ToString() ?? string.Empty;
			}
		}

		static string QuoteString(string s) {
			var sb = new StringBuilder(s.Length + 2);
			sb.Append('"');
			int n = 0;
			foreach (var c in s) {
				if (n++ >= MaxStringChars) {
					sb.Append("...");
					break;
				}
				switch (c) {
				case '"': sb.Append("\\\""); break;
				case '\\': sb.Append("\\\\"); break;
				case '\n': sb.Append("\\n"); break;
				case '\r': sb.Append("\\r"); break;
				case '\t': sb.Append("\\t"); break;
				case '\0': sb.Append("\\0"); break;
				default:
					if (char.IsControl(c) || char.IsSurrogate(c) || c == (char)0x2028 || c == (char)0x2029)
						sb.Append("\\u").Append(((int)c).ToString("X4"));
					else
						sb.Append(c);
					break;
				}
			}
			sb.Append('"');
			return sb.ToString();
		}

		/// <summary>Comments must stay on one line; also neutralise anything that could end a block comment.</summary>
		static string OneLine(string s) {
			var sb = new StringBuilder(s.Length);
			foreach (var c in s)
				sb.Append(c == '\r' || c == '\n' || c == (char)0x2028 || c == (char)0x2029 ? ' ' : c);
			return sb.ToString();
		}
	}
}
