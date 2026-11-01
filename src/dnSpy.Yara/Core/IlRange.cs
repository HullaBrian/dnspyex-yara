using System;
using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace dnSpy.Yara.Core {
	/// <summary>A contiguous run of IL instructions inside one method body.</summary>
	public sealed class IlRange {
		public MethodDef Method { get; }
		public IList<Instruction> Instructions { get; }

		public IlRange(MethodDef method, IList<Instruction> instructions) {
			Method = method ?? throw new ArgumentNullException(nameof(method));
			Instructions = instructions ?? throw new ArgumentNullException(nameof(instructions));
		}

		public uint StartOffset => Instructions.Count == 0 ? 0 : Instructions[0].Offset;
		public uint EndOffset => Instructions.Count == 0 ? 0 : Instructions[^1].Offset + (uint)Instructions[^1].GetSize();

		/// <summary>The whole body of <paramref name="method"/>, or null if it has no IL.</summary>
		public static IlRange? WholeMethod(MethodDef method) {
			if (method?.Body is not CilBody body || body.Instructions.Count == 0)
				return null;
			return new IlRange(method, body.Instructions.ToArray());
		}
	}

	/// <summary>
	/// Collects IL offset spans (from selected statements / instructions) per method and turns them into
	/// <see cref="IlRange"/>s. Each method yields one contiguous range covering everything selected in it, because a
	/// YARA hex string matches a contiguous run of bytes anyway, and selections in the C# view often leave small gaps
	/// (hidden sequence points, nops, compiler-generated branches) between the IL of adjacent statements.
	/// </summary>
	public sealed class IlRangeBuilder {
		readonly List<MethodDef> order = new List<MethodDef>();
		readonly Dictionary<MethodDef, (uint start, uint end)> spans = new Dictionary<MethodDef, (uint, uint)>();

		public bool IsEmpty => order.Count == 0;

		public void Add(MethodDef method, uint start, uint end) {
			if (method is null || end <= start)
				return;
			if (spans.TryGetValue(method, out var s))
				spans[method] = (Math.Min(s.start, start), Math.Max(s.end, end));
			else {
				order.Add(method);
				spans[method] = (start, end);
			}
		}

		public void Add(MethodDef method, Instruction instr) => Add(method, instr.Offset, instr.Offset + (uint)instr.GetSize());

		public List<IlRange> Build() {
			var result = new List<IlRange>();
			foreach (var method in order) {
				if (method.Body is not CilBody body)
					continue;
				var (start, end) = spans[method];
				var instrs = body.Instructions.Where(i => i.Offset >= start && i.Offset < end).ToArray();
				if (instrs.Length > 0)
					result.Add(new IlRange(method, instrs));
			}
			return result;
		}
	}
}
