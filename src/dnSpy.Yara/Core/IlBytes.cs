using System;
using System.Collections.Generic;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace dnSpy.Yara.Core {
	/// <summary>Bytes of one instruction. A value of -1 means "unknown" and is always emitted as <c>??</c>.</summary>
	public readonly struct InstructionBytes {
		public Instruction Instruction { get; }
		public short[] Bytes { get; }
		/// <summary>Number of leading bytes that make up the opcode (1 or 2).</summary>
		public int OpCodeSize { get; }

		public InstructionBytes(Instruction instruction, short[] bytes, int opCodeSize) {
			Instruction = instruction;
			Bytes = bytes;
			OpCodeSize = opCodeSize;
		}
	}

	public enum IlBytesSource {
		/// <summary>Exact bytes from the PE image.</summary>
		File,
		/// <summary>The body differs from the file (edited in dnSpy), bytes were re-encoded.</summary>
		ReEncodedModified,
		/// <summary>No file bytes available (in-memory/new method), bytes were re-encoded.</summary>
		ReEncodedNoFileBytes,
	}

	/// <summary>
	/// Reads the bytes of IL instructions. The original bytes are read straight from the PE image whenever possible so
	/// that the generated hex string matches the file on disk exactly. If that isn't possible (method created or edited
	/// in dnSpy, module loaded from memory without a usable image, ...) the instruction is re-encoded from dnlib's
	/// object model and any byte that can't be known (e.g. a user-string token) becomes a wildcard.
	/// </summary>
	public static class IlBytes {
		/// <summary>
		/// Reads the bytes of every instruction in <paramref name="range"/>. The original file bytes are used only if
		/// every byte that can be re-encoded from the object model agrees with them; otherwise the body was edited
		/// in dnSpy (or dnlib's view differs from the file) and the re-encoded bytes are used instead.
		/// </summary>
		public static List<InstructionBytes> Read(IlRange range, out IlBytesSource source) {
			var code = TryReadOriginalCode(range.Method);
			var encoded = new List<InstructionBytes>(range.Instructions.Count);
			// If dnlib's view of the whole body doesn't line up with the file, the body was edited (or is odd).
			var lastInstr = range.Method.Body.Instructions[^1];
			bool matches = code is not null && lastInstr.Offset + (uint)lastInstr.GetSize() == (uint)code.Length;
			foreach (var instr in range.Instructions) {
				int size = instr.GetSize();
				var bytes = Encode(instr, size);
				encoded.Add(new InstructionBytes(instr, bytes, instr.OpCode.Size));
				if (matches) {
					if (instr.Offset + (uint)size > (uint)code!.Length)
						matches = false;
					else {
						for (int i = 0; i < size && matches; i++) {
							if (bytes[i] >= 0 && bytes[i] != code[instr.Offset + i])
								matches = false;
						}
					}
				}
			}
			if (!matches) {
				source = code is null ? IlBytesSource.ReEncodedNoFileBytes : IlBytesSource.ReEncodedModified;
				return encoded;
			}

			source = IlBytesSource.File;
			var result = new List<InstructionBytes>(encoded.Count);
			foreach (var e in encoded) {
				var instr = e.Instruction;
				var bytes = new short[e.Bytes.Length];
				for (int i = 0; i < bytes.Length; i++)
					bytes[i] = code![instr.Offset + i];
				result.Add(new InstructionBytes(instr, bytes, e.OpCodeSize));
			}
			return result;
		}

		/// <summary>Returns the method's raw IL code bytes from the PE image, or null if unavailable / inconsistent.</summary>
		public static byte[]? TryReadOriginalCode(MethodDef method) {
			try {
				if (method is MethodDefUser || method.Module is not ModuleDefMD mod || method.RVA == 0)
					return null;
				if (method.Body is not CilBody body || body.Instructions.Count == 0)
					return null;
				var reader = mod.Metadata.PEImage.CreateReader(method.RVA);
				uint start = reader.Position;
				byte b = reader.ReadByte();
				uint codeSize;
				switch (b & 3) {
				case 2: // tiny header
					codeSize = (uint)(b >> 2);
					break;
				case 3: // fat header
					reader.Position = start;
					ushort flags = reader.ReadUInt16();
					uint headerSize = (uint)(flags >> 12) * 4;
					reader.ReadUInt16(); // max stack
					codeSize = reader.ReadUInt32();
					reader.Position = start + headerSize;
					break;
				default:
					return null;
				}
				return reader.ReadBytes((int)codeSize);
			}
			catch {
				return null;
			}
		}

		/// <summary>Re-encodes an instruction. Unknowable bytes are -1.</summary>
		static short[] Encode(Instruction instr, int size) {
			var bytes = new short[size];
			for (int i = 0; i < size; i++)
				bytes[i] = -1;
			int pos = 0;
			ushort op = (ushort)instr.OpCode.Value;
			if (instr.OpCode.Size == 2) {
				bytes[pos++] = (byte)(op >> 8);
				bytes[pos++] = (byte)op;
			}
			else
				bytes[pos++] = (byte)op;

			void Put(ulong value, int n) {
				for (int i = 0; i < n && pos < size; i++)
					bytes[pos++] = (byte)(value >> (8 * i));
			}
			void Skip(int n) => pos += n;
			int nextOffset = (int)instr.Offset + size;

			switch (instr.OpCode.OperandType) {
			case OperandType.InlineBrTarget:
				if (instr.Operand is Instruction t4) Put((uint)((int)t4.Offset - nextOffset), 4); else Skip(4);
				break;
			case OperandType.ShortInlineBrTarget:
				if (instr.Operand is Instruction t1) Put((byte)(sbyte)((int)t1.Offset - nextOffset), 1); else Skip(1);
				break;
			case OperandType.InlineSwitch:
				if (instr.Operand is IList<Instruction> targets) {
					Put((uint)targets.Count, 4);
					foreach (var t in targets) {
						if (t is null) Skip(4); else Put((uint)((int)t.Offset - nextOffset), 4);
					}
				}
				break;
			case OperandType.InlineField:
			case OperandType.InlineMethod:
			case OperandType.InlineTok:
			case OperandType.InlineType:
			case OperandType.InlineSig:
				// Members loaded from the file still know their original token; new ones (rid 0) don't.
				if (instr.Operand is IMDTokenProvider tp && tp.MDToken.Rid != 0)
					Put(tp.MDToken.Raw, 4);
				else if (instr.Operand is IMDTokenProvider tp2) {
					Skip(3);
					Put((byte)tp2.MDToken.Table, 1);
				}
				break;
			case OperandType.InlineString:
				Skip(3); // #US heap offset isn't kept by dnlib
				Put(0x70, 1);
				break;
			case OperandType.InlineI:
				Put((uint)Convert.ToInt32(instr.Operand ?? 0), 4);
				break;
			case OperandType.InlineI8:
				Put((ulong)Convert.ToInt64(instr.Operand ?? 0L), 8);
				break;
			case OperandType.ShortInlineI:
				Put(instr.Operand is sbyte sb ? (byte)sb : Convert.ToByte(instr.Operand ?? (byte)0), 1);
				break;
			case OperandType.InlineR:
				Put((ulong)BitConverter.DoubleToInt64Bits(Convert.ToDouble(instr.Operand ?? 0d)), 8);
				break;
			case OperandType.ShortInlineR:
				Put((uint)BitConverter.SingleToInt32Bits(Convert.ToSingle(instr.Operand ?? 0f)), 4);
				break;
			case OperandType.InlineVar:
				Put((ushort)GetVarIndex(instr.Operand), 2);
				break;
			case OperandType.ShortInlineVar:
				Put((byte)GetVarIndex(instr.Operand), 1);
				break;
			}
			return bytes;
		}

		static int GetVarIndex(object? operand) => operand switch {
			Local l => l.Index,
			Parameter p => p.Index, // includes the hidden 'this' parameter, same as the IL operand
			_ => 0,
		};
	}
}
