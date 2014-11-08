
$local = Get-Location;
$bin = Join-Path $local "bin"

$pythonDir = $bin + "\python27"
$python = $pythonDir + "\python.exe"

#Update the PATH variable so python will be able to detect openssl
$Env:Path = "$bin\OpenSSL\;$Env:Path"

Start-Process "$pythonDir\scripts\nosetests.exe" -NoNewWindow "--with-coverage --cover-package=node --cover-inclusive"
