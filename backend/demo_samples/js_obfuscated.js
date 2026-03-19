// Demo: Array-based string obfuscation + base64 + eval
var _0x4a2b = ['aHR0cDovL2V4YW1wbGUuY29tL2MycGF5bG9hZA==', 'bG9jYWxTdG9yYWdl', 'Z2V0SXRlbQ==', 'c2V0SXRlbQ==', 'dXNlcl90b2tlbg==', 'YWRtaW4=', 'Y3JlZGVudGlhbHM='];
(function(_0x1a2b3c, _0x4a2b5d) {
    var _0x1f3a = function(_0x2d1e4f) {
        while (--_0x2d1e4f) {
            _0x1a2b3c['push'](_0x1a2b3c['shift']());
        }
    };
    _0x1f3a(++_0x4a2b5d);
}(_0x4a2b, 0x1a3));
var _0xf1 = function(_0x1, _0x2) {
    _0x1 = _0x1 - 0x0;
    var _0x3 = _0x4a2b[_0x1];
    if (_0xf1['initialized'] === undefined) {
        _0xf1['base64decode'] = function(_0x4) {
            var _0x5 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
            var _0x6 = '', _0x7 = '';
            for (var _0x8 = 0x0, _0x9, _0xa, _0xb = 0x0; _0xa = _0x4['charAt'](_0xb++);) {
                _0x9 = _0x5['indexOf'](_0xa);
                if (~_0x9) {
                    _0x6 += _0x8 % 0x4 ? String.fromCharCode(0xff & _0x6a >> (-0x2 * _0x8 & 0x6)) : 0x0;
                    _0x8++;
                }
            }
            return _0x6;
        };
        _0xf1['initialized'] = true;
    }
    return _0x3;
};
var url = atob(_0xf1('0x0'));
var storage = _0xf1('0x1');
eval('console' + '.' + 'log' + '(' + '"loaded"' + ')');
