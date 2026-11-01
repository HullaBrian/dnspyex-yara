using System;
using System.ComponentModel.Composition;
using dnSpy.Contracts.Settings;
using dnSpy.Yara.Core;

namespace dnSpy.Yara {
	/// <summary>User options, persisted in dnSpy's settings file.</summary>
	[Export(typeof(YaraSettings))]
	sealed class YaraSettings {
		static readonly Guid SETTINGS_GUID = new Guid("8C0B7E52-3F5E-4D7C-9B8E-5A3F1C2D4E61");
		readonly ISettingsService settingsService;

		bool wildcardTokens = true;
		bool wildcardBranches;
		bool includeStrings = true;
		string author = string.Empty;

		[ImportingConstructor]
		YaraSettings(ISettingsService settingsService) {
			this.settingsService = settingsService;
			var sect = settingsService.GetOrCreateSection(SETTINGS_GUID);
			wildcardTokens = sect.Attribute<bool?>(nameof(WildcardTokens)) ?? wildcardTokens;
			wildcardBranches = sect.Attribute<bool?>(nameof(WildcardBranches)) ?? wildcardBranches;
			includeStrings = sect.Attribute<bool?>(nameof(IncludeStrings)) ?? includeStrings;
			author = sect.Attribute<string>(nameof(Author)) ?? author;
		}

		public bool WildcardTokens {
			get => wildcardTokens;
			set { wildcardTokens = value; Save(); }
		}

		public bool WildcardBranches {
			get => wildcardBranches;
			set { wildcardBranches = value; Save(); }
		}

		public bool IncludeStrings {
			get => includeStrings;
			set { includeStrings = value; Save(); }
		}

		/// <summary>Value of the rule's <c>author</c> meta field (edit dnSpy's settings XML to change it).</summary>
		public string Author {
			get => author;
			set { author = value ?? string.Empty; Save(); }
		}

		public YaraOptions ToOptions() => new YaraOptions {
			WildcardTokens = WildcardTokens,
			WildcardBranches = WildcardBranches,
			IncludeStrings = IncludeStrings,
			Author = Author,
			Now = DateTime.Now,
		};

		void Save() {
			var sect = settingsService.RecreateSection(SETTINGS_GUID);
			sect.Attribute(nameof(WildcardTokens), wildcardTokens);
			sect.Attribute(nameof(WildcardBranches), wildcardBranches);
			sect.Attribute(nameof(IncludeStrings), includeStrings);
			sect.Attribute(nameof(Author), author);
		}
	}
}
