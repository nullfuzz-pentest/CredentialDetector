# Compila la extension Montoya y genera el JAR.
# Uso:  powershell -ExecutionPolicy Bypass -File build.ps1
$ErrorActionPreference = "Stop"

$root = $PSScriptRoot
$apiJar = Join-Path $root "lib\montoya-api-2026.7.jar"
$buildDir = Join-Path $root "build"
$outJar = Join-Path $root "CredentialDetector.jar"

# jar.exe puede no estar en el PATH aunque javac si; lo buscamos junto al JDK.
$javac = (Get-Command javac).Source
$jarExe = "jar"
if (-not (Get-Command jar -ErrorAction SilentlyContinue)) {
    $candidate = "C:\Program Files\Java\jdk-22\bin\jar.exe"
    if (Test-Path $candidate) { $jarExe = $candidate }
}

Write-Host "Limpiando build..."
Remove-Item -Recurse -Force $buildDir -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $buildDir | Out-Null

Write-Host "Compilando (Java 21)..."
$sources = Get-ChildItem -Recurse (Join-Path $root "src") -Filter *.java | ForEach-Object { $_.FullName }
javac --release 21 -cp $apiJar -d $buildDir $sources

Write-Host "Empaquetando JAR..."
& $jarExe cfm $outJar (Join-Path $root "manifest.txt") -C $buildDir .

Write-Host "Listo: $outJar"
