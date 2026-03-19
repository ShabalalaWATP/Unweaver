// Demo: C# obfuscation with reflection, base64, string construction
using System;
using System.Reflection;
using System.Text;
class _0x1f {
    static string _0xa1(string s) { return Encoding.UTF8.GetString(Convert.FromBase64String(s)); }
    static void _0x2b() {
        var _0x3c = _0xa1("U3lzdGVtLkRpYWdub3N0aWNzLlByb2Nlc3M=");
        var _0x4d = _0xa1("U3RhcnQ=");
        string cmd = _0xa1("Y21k") + "." + _0xa1("ZXhl");
        Type t = Type.GetType(_0x3c);
        MethodInfo m = t.GetMethod(_0x4d, new Type[] { typeof(string) });
        m.Invoke(null, new object[] { cmd });
    }
}
