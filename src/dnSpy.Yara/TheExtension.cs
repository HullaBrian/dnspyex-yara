using System.Collections.Generic;
using dnSpy.Contracts.Extension;

namespace dnSpy.Yara {
	[ExportExtension]
	sealed class TheExtension : IExtension {
		public IEnumerable<string> MergedResourceDictionaries {
			get { yield break; }
		}

		public ExtensionInfo ExtensionInfo => new ExtensionInfo {
			ShortDescription = "Create YARA hex strings / rules (with IL comments) from selected code",
		};

		public void OnEvent(ExtensionEvent @event, object? obj) { }
	}
}
