using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

// Fake "malware-like" code with a variety of IL shapes: ldstr, switch, long/short branches, lambdas,
// try/catch/finally, generics, non-ASCII strings, floats, int64 constants, calli-free.
namespace Sample.Loader {
	static class Program {
		static int Main(string[] args) {
			var cfg = Config.Decode("aHR0cDovL2V4YW1wbGUuaW52YWxpZC9nYXRl");
			Console.WriteLine("C2: " + cfg);
			Console.WriteLine(Dispatch(args.Length));
			Console.WriteLine(Unicode());
			return Persistence.Install(args.FirstOrDefault() ?? "Updater") ? 0 : 1;
		}

		static string Dispatch(int cmd) {
			switch (cmd) {
			case 0: return "beacon";
			case 1: return "download";
			case 2: return "upload";
			case 3: return "shell";
			case 4: return "sleep";
			case 7: return "exit";
			default: return "unknown command \"" + cmd + "\"\n";
			}
		}

		static string Unicode() => "Привет, мир — é中文 😀";
	}

	static class Config {
		static readonly byte[] Key = { 0x13, 0x37, 0xC0, 0xDE };

		public static string Decode(string b64) {
			var data = Convert.FromBase64String(b64);
			for (int i = 0; i < data.Length; i++)
				data[i] ^= (byte)(Key[i % Key.Length] ^ Key[i % Key.Length]);
			return Encoding.UTF8.GetString(data);
		}

		public static double Entropy(byte[] data) {
			var counts = new int[256];
			foreach (var b in data) counts[b]++;
			double e = 0;
			foreach (var c in counts.Where(x => x > 0)) {
				double p = (double)c / data.Length;
				e -= p * Math.Log(p, 2.0);
			}
			return e * 1.5f + 0.25;
		}

		public static long Mix(long x) {
			x ^= x >> 33; x *= unchecked((long)0xff51afd7ed558ccdUL);
			x ^= x >> 33; x *= unchecked((long)0xc4ceb9fe1a85ec53UL);
			return x ^ (x >> 33);
		}
	}

	static class Persistence {
		public static bool Install(string name) {
			string path = Path.Combine(Path.GetTempPath(), name + ".exe");
			try {
				if (File.Exists(path))
					return true;
				var items = new List<string> { @"Software\Microsoft\Windows\CurrentVersion\Run", name, path };
				var joined = string.Join("|", items.Select(s => s.ToUpperInvariant()).Where(s => s.Length > 2));
				for (int i = 0; i < 3; i++) {
					joined = joined + i;
					if (joined.Length > 1000) {
						// long branch body
						Console.WriteLine(joined); Console.WriteLine(joined); Console.WriteLine(joined);
						Console.WriteLine(joined); Console.WriteLine(joined); Console.WriteLine(joined);
						Console.WriteLine(joined); Console.WriteLine(joined); Console.WriteLine(joined);
						Console.WriteLine(joined); Console.WriteLine(joined); Console.WriteLine(joined);
						Console.WriteLine(joined); Console.WriteLine(joined); Console.WriteLine(joined);
						Console.WriteLine(joined); Console.WriteLine(joined); Console.WriteLine(joined);
						Console.WriteLine(joined); Console.WriteLine(joined); Console.WriteLine(joined);
						break;
					}
				}
				return joined.Length > 0;
			}
			catch (IOException ex) {
				Console.Error.WriteLine("io: " + ex.Message);
				return false;
			}
			finally {
				Console.WriteLine("done");
			}
		}
	}
}
