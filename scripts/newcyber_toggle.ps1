param(
  [Parameter(Mandatory = $true)][string]$AppDir,
  [ValidateSet('Toggle', 'Status')][string]$Action = 'Toggle'
)

$ErrorActionPreference = 'Stop'

try {
  $root = [System.IO.Path]::GetFullPath($AppDir).TrimEnd([char]'\')
  $electron = Join-Path $root 'node_modules\electron\dist\electron.exe'
  $processes = @(Get-CimInstance Win32_Process -Filter "Name = 'electron.exe'" | Where-Object {
    [string]::Equals($_.ExecutablePath, $electron, [System.StringComparison]::OrdinalIgnoreCase) -and
    $_.CommandLine -and
    $_.CommandLine.IndexOf($root, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -and
    $_.CommandLine -notmatch '(?:^|\s)--type='
  })

  if ($processes.Count -eq 0) {
    Write-Host 'NewCyber is not running. Starting...'
    exit 10
  }
  if ($Action -eq 'Status') {
    Write-Host 'NewCyber is running.'
    exit 0
  }

  $closed = $false
  foreach ($item in $processes) {
    try {
      $process = Get-Process -Id $item.ProcessId -ErrorAction Stop
      if ($process.MainWindowHandle -ne [IntPtr]::Zero) {
        $closed = $process.CloseMainWindow() -or $closed
      }
    } catch [System.ArgumentException] {
      # The process exited between discovery and close.
      $closed = $true
    }
  }
  if (-not $closed) {
    Write-Error 'NewCyber was found, but its window could not be closed. Close it manually.'
    exit 2
  }
  Write-Host 'NewCyber close request sent.'
  exit 0
} catch {
  Write-Error "NewCyber toggle failed: $($_.Exception.Message)"
  exit 2
}
