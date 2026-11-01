using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;
using dnSpy.Contracts.Decompiler;
using dnSpy.Contracts.Documents.Tabs.DocViewer;
using dnSpy.Contracts.Documents.TreeView;
using dnSpy.Contracts.TreeView;
using dnSpy.Yara.Core;

namespace dnSpy.Yara {
	/// <summary>Maps what the user selected in dnSpy to IL ranges.</summary>
	static class YaraSelection {
		/// <summary>
		/// Resolution order:
		///  1. Selection in the IL view: the selected instruction labels (exact instructions).
		///  2. Selection in a decompiled view (C#/VB): every statement intersecting the selection.
		///  3. Selection that only covers declarations: the whole body of each method declared in it.
		///  4. No selection: the method declaration under the cursor (whole body), else the statement under it.
		/// </summary>
		/// <param name="position">Text position to use when nothing is selected (mouse position for a context menu,
		/// caret otherwise).</param>
		public static List<IlRange> FromDocumentViewer(IDocumentViewer? viewer, TextReference? clickedRef, int? position) {
			var builder = new IlRangeBuilder();
			if (viewer is null)
				return builder.Build();

			if (!viewer.Selection.IsEmpty) {
				var refs = viewer.GetSelectedReferences().ToList();
				foreach (var r in refs) {
					if (r.Data.IsDefinition && r.Data.Reference is InstructionReference ir && ir.Method is not null)
						builder.Add(ir.Method, ir.Instruction);
				}
				if (builder.IsEmpty) {
					var debugService = viewer.GetMethodDebugService();
					foreach (var span in viewer.Selection.SelectedSpans) {
						foreach (var st in debugService.GetStatementsByTextSpan(span.Span))
							builder.Add(st.Method, st.Statement.ILSpan.Start, st.Statement.ILSpan.End);
					}
				}
				if (builder.IsEmpty) {
					foreach (var r in refs) {
						if (r.Data.IsDefinition && r.Data.Reference is MethodDef md)
							AddWholeMethod(builder, md);
					}
				}
				return builder.Build();
			}

			if (clickedRef is not null && clickedRef.IsDefinition) {
				if (clickedRef.Reference is MethodDef md) {
					AddWholeMethod(builder, md);
					return builder.Build();
				}
				if (clickedRef.Reference is InstructionReference ir && ir.Method is not null) {
					builder.Add(ir.Method, ir.Instruction);
					return builder.Build();
				}
			}

			int pos = position ?? viewer.Caret.Position.BufferPosition.Position;
			foreach (var st in viewer.GetMethodDebugService().FindByTextPosition(pos, FindByTextPositionOptions.SameMethod))
				builder.Add(st.Method, st.Statement.ILSpan.Start, st.Statement.ILSpan.End);
			return builder.Build();
		}

		public static List<IlRange> FromTreeNodes(IEnumerable<TreeNodeData>? nodes) {
			var result = new List<IlRange>();
			if (nodes is null)
				return result;
			foreach (var node in nodes) {
				if (node is MethodNode mn && IlRange.WholeMethod(mn.MethodDef) is IlRange range)
					result.Add(range);
			}
			return result;
		}

		static void AddWholeMethod(IlRangeBuilder builder, MethodDef md) {
			if (IlRange.WholeMethod(md) is IlRange r)
				builder.Add(md, r.StartOffset, r.EndOffset);
		}
	}
}
