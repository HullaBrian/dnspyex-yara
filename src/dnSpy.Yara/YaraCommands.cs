using System;
using System.Collections.Generic;
using System.ComponentModel.Composition;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows;
using System.Windows.Input;
using dnSpy.Contracts.App;
using dnSpy.Contracts.Controls;
using dnSpy.Contracts.Documents.Tabs;
using dnSpy.Contracts.Documents.Tabs.DocViewer;
using dnSpy.Contracts.Extension;
using dnSpy.Contracts.Images;
using dnSpy.Contracts.Menus;
using dnSpy.Contracts.Text;
using dnSpy.Contracts.TreeView;
using dnSpy.Yara.Core;

namespace dnSpy.Yara {
	static class YaraConstants {
		public const string SUBMENU_GUID = "3E7C4F0A-6B21-4C8E-A5D9-0F1B2C3D4E5F";
		// Sits between "Other" (14000) and the editor Copy/Find group (15000) in the code view menu.
		public const string GROUP_CTX = "14500,9D2E6A41-7C3B-4F58-8E1A-2B3C4D5E6F70";
		public const string GROUP_SUB_COPY = "0,A1B2C3D4-1111-4E5F-8A9B-0C1D2E3F4A5B";
		public const string GROUP_SUB_OPTIONS = "1000,A1B2C3D4-2222-4E5F-8A9B-0C1D2E3F4A5B";
		public const string CopyStringGesture = "Ctrl+Alt+Y";
		public const string CopyRuleGesture = "Ctrl+Alt+Shift+Y";
	}

	sealed class YaraContext {
		public List<IlRange> Ranges { get; }
		public YaraContext(List<IlRange> ranges) => Ranges = ranges;
		public int InstructionCount => Ranges.Sum(r => r.Instructions.Count);
	}

	/// <summary>Shared context creation: all YARA menu items share one cached <see cref="YaraContext"/> per menu.</summary>
	abstract class YaraMenuItemBase : MenuItemBase<YaraContext> {
		static readonly object ContextKey = new object();
		protected sealed override object CachedContextKey => ContextKey;

		protected sealed override YaraContext? CreateContext(IMenuItemContext context) {
			List<IlRange> ranges;
			if (context.CreatorObject.Guid == new Guid(MenuConstants.GUIDOBJ_DOCUMENTVIEWERCONTROL_GUID)) {
				ranges = YaraSelection.FromDocumentViewer(context.Find<IDocumentViewer>(), context.Find<TextReference>(), context.Find<TextEditorPosition>()?.Position);
			}
			else if (context.CreatorObject.Guid == new Guid(MenuConstants.GUIDOBJ_DOCUMENTS_TREEVIEW_GUID))
				ranges = YaraSelection.FromTreeNodes(context.Find<TreeNodeData[]>());
			else
				return null;
			return ranges.Count == 0 ? null : new YaraContext(ranges);
		}
	}

	[ExportMenuItem(Header = "YARA", Icon = DsImagesAttribute.Binary, Guid = YaraConstants.SUBMENU_GUID, Group = YaraConstants.GROUP_CTX, Order = 0)]
	sealed class YaraSubMenu : YaraMenuItemBase {
		public override void Execute(YaraContext context) { }
	}

	[ExportMenuItem(OwnerGuid = YaraConstants.SUBMENU_GUID, Header = "Copy YARA Hex String", Icon = DsImagesAttribute.Copy, InputGestureText = YaraConstants.CopyStringGesture, Group = YaraConstants.GROUP_SUB_COPY, Order = 0)]
	sealed class CopyYaraStringCommand : YaraMenuItemBase {
		readonly YaraSettings settings;
		[ImportingConstructor]
		CopyYaraStringCommand(YaraSettings settings) => this.settings = settings;
		public override string? GetHeader(YaraContext context) => $"Copy YARA Hex String ({Describe(context)})";
		public override void Execute(YaraContext context) => YaraActions.Copy(settings, context.Ranges, rule: false);
		internal static string Describe(YaraContext c) {
			int n = c.InstructionCount;
			var s = $"{n} instruction{(n == 1 ? "" : "s")}";
			return c.Ranges.Count > 1 ? $"{s} in {c.Ranges.Count} methods" : s;
		}
	}

	[ExportMenuItem(OwnerGuid = YaraConstants.SUBMENU_GUID, Header = "Copy YARA Rule", Icon = DsImagesAttribute.Copy, InputGestureText = YaraConstants.CopyRuleGesture, Group = YaraConstants.GROUP_SUB_COPY, Order = 10)]
	sealed class CopyYaraRuleCommand : YaraMenuItemBase {
		readonly YaraSettings settings;
		[ImportingConstructor]
		CopyYaraRuleCommand(YaraSettings settings) => this.settings = settings;
		public override string? GetHeader(YaraContext context) => $"Copy YARA Rule ({CopyYaraStringCommand.Describe(context)})";
		public override void Execute(YaraContext context) => YaraActions.Copy(settings, context.Ranges, rule: true);
	}

	[ExportMenuItem(OwnerGuid = YaraConstants.SUBMENU_GUID, Header = "Wildcard Metadata Tokens", Group = YaraConstants.GROUP_SUB_OPTIONS, Order = 0)]
	sealed class ToggleWildcardTokensCommand : YaraMenuItemBase {
		readonly YaraSettings settings;
		[ImportingConstructor]
		ToggleWildcardTokensCommand(YaraSettings settings) => this.settings = settings;
		public override bool IsChecked(YaraContext context) => settings.WildcardTokens;
		public override void Execute(YaraContext context) => settings.WildcardTokens = !settings.WildcardTokens;
	}

	[ExportMenuItem(OwnerGuid = YaraConstants.SUBMENU_GUID, Header = "Wildcard Branch Offsets", Group = YaraConstants.GROUP_SUB_OPTIONS, Order = 10)]
	sealed class ToggleWildcardBranchesCommand : YaraMenuItemBase {
		readonly YaraSettings settings;
		[ImportingConstructor]
		ToggleWildcardBranchesCommand(YaraSettings settings) => this.settings = settings;
		public override bool IsChecked(YaraContext context) => settings.WildcardBranches;
		public override void Execute(YaraContext context) => settings.WildcardBranches = !settings.WildcardBranches;
	}

	[ExportMenuItem(OwnerGuid = YaraConstants.SUBMENU_GUID, Header = "Add ldstr Literals to Rule", Group = YaraConstants.GROUP_SUB_OPTIONS, Order = 20)]
	sealed class ToggleIncludeStringsCommand : YaraMenuItemBase {
		readonly YaraSettings settings;
		[ImportingConstructor]
		ToggleIncludeStringsCommand(YaraSettings settings) => this.settings = settings;
		public override bool IsChecked(YaraContext context) => settings.IncludeStrings;
		public override void Execute(YaraContext context) => settings.IncludeStrings = !settings.IncludeStrings;
	}

	/// <summary>Keyboard shortcuts in the code view (they act on the selection, or the statement at the caret).</summary>
	[ExportAutoLoaded]
	sealed class YaraKeyboardShortcuts : IAutoLoaded {
		static readonly RoutedCommand CopyStringCommand = new RoutedCommand("CopyYaraStringCommand", typeof(YaraKeyboardShortcuts));
		static readonly RoutedCommand CopyRuleCommand = new RoutedCommand("CopyYaraRuleCommand", typeof(YaraKeyboardShortcuts));
		readonly IDocumentTabService documentTabService;
		readonly YaraSettings settings;

		[ImportingConstructor]
		YaraKeyboardShortcuts(IWpfCommandService wpfCommandService, IDocumentTabService documentTabService, YaraSettings settings) {
			this.documentTabService = documentTabService;
			this.settings = settings;
			var cmds = wpfCommandService.GetCommands(ControlConstants.GUID_DOCUMENTVIEWER_UICONTEXT);
			cmds.Add(CopyStringCommand, (s, e) => Run(rule: false), (s, e) => e.CanExecute = true, ModifierKeys.Control | ModifierKeys.Alt, Key.Y);
			cmds.Add(CopyRuleCommand, (s, e) => Run(rule: true), (s, e) => e.CanExecute = true, ModifierKeys.Control | ModifierKeys.Alt | ModifierKeys.Shift, Key.Y);
		}

		void Run(bool rule) {
			var viewer = documentTabService.ActiveTab.TryGetDocumentViewer();
			var ranges = YaraSelection.FromDocumentViewer(viewer, null, null);
			if (ranges.Count == 0) {
				MsgBox.Instance.Show("No IL found at the caret or in the selection. Select code in a method body (C# or IL view) first.");
				return;
			}
			YaraActions.Copy(settings, ranges, rule);
		}
	}

	static class YaraActions {
		public static void Copy(YaraSettings settings, List<IlRange> ranges, bool rule) {
			string text;
			try {
				var gen = new YaraGenerator(settings.ToOptions());
				text = rule ? gen.GenerateRule(ranges) : gen.GenerateStrings(ranges);
			}
			catch (Exception ex) {
				MsgBox.Instance.Show("Failed to generate YARA output:\n\n" + ex);
				return;
			}
			SetClipboard(text.Replace("\n", Environment.NewLine));
		}

		static void SetClipboard(string text) {
			// The clipboard is occasionally locked by another process; retry briefly like other dnSpy copy commands.
			for (int attempt = 0; ; attempt++) {
				try {
					Clipboard.SetText(text);
					return;
				}
				catch (ExternalException) when (attempt < 5) {
					Thread.Sleep(50);
				}
				catch (ExternalException ex) {
					MsgBox.Instance.Show("Could not access the clipboard: " + ex.Message);
					return;
				}
			}
		}
	}
}
