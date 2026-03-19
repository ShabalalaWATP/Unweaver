# Demo: Python obfuscation with base64, exec, marshal
import base64, codecs
_x = 'aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ2VjaG8gZGVtbycp'
exec(base64.b64decode(_x))
_y = codecs.decode('vzcbeg bf', 'rot_13')
_z = ''.join([chr(x) for x in [104, 116, 116, 112, 58, 47, 47, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109]])
exec(base64.b64decode(base64.b64decode('YVcxd2IzSjBJSE52WTJ0bGRBPT0=')))
