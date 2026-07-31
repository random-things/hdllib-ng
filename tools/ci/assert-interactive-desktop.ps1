[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

if ($env:OS -ne 'Windows_NT') {
    throw 'GUI tests require Windows.'
}

$process = Get-Process -Id $PID
if ($process.SessionId -eq 0) {
    throw 'The runner is in Windows session 0. Start run.cmd from an interactive user session.'
}

if ($env:SESSIONNAME -eq 'Services') {
    throw 'The runner is attached to the Services session, not an interactive desktop.'
}

$explorer = Get-Process -Name explorer -ErrorAction SilentlyContinue |
    Where-Object { $_.SessionId -eq $process.SessionId } |
    Select-Object -First 1
if ($null -eq $explorer) {
    throw "No Explorer shell is running in session $($process.SessionId)."
}

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class HdlWindowStationProbe
{
    [StructLayout(LayoutKind.Sequential)]
    public struct UserObjectFlags
    {
        public bool Inherit;
        public bool Reserved;
        public uint Flags;
    }

    [DllImport("user32.dll", SetLastError = true)]
    public static extern IntPtr GetProcessWindowStation();

    [DllImport("user32.dll", SetLastError = true)]
    public static extern bool GetUserObjectInformation(
        IntPtr handle,
        int index,
        ref UserObjectFlags info,
        uint length,
        out uint needed);
}
'@

$flags = New-Object HdlWindowStationProbe+UserObjectFlags
$needed = 0
$station = [HdlWindowStationProbe]::GetProcessWindowStation()
$size = [Runtime.InteropServices.Marshal]::SizeOf($flags)
$ok = [HdlWindowStationProbe]::GetUserObjectInformation(
    $station,
    1,
    [ref]$flags,
    $size,
    [ref]$needed)
if (-not $ok -or ($flags.Flags -band 1) -eq 0) {
    throw 'The runner process is not attached to a visible interactive window station.'
}

Add-Type -AssemblyName System.Windows.Forms
if ([System.Windows.Forms.Screen]::AllScreens.Count -lt 1) {
    throw 'Windows reports no available display.'
}

$form = New-Object System.Windows.Forms.Form
try {
    $form.ShowInTaskbar = $false
    $form.Opacity = 0
    $form.StartPosition = 'Manual'
    $form.Location = [System.Drawing.Point]::new(-32000, -32000)
    $form.Show()
    [System.Windows.Forms.Application]::DoEvents()
    if (-not $form.IsHandleCreated) {
        throw 'Windows could not create a GUI window on the runner desktop.'
    }
}
finally {
    $form.Close()
    $form.Dispose()
}

Write-Host "Interactive desktop ready: session=$($process.SessionId), name=$env:SESSIONNAME"
