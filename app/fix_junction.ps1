# Fix junction - remove broken one and recreate with correct Korean path
if (Test-Path 'C:\android-sdk') {
    Remove-Item 'C:\android-sdk' -Force -Recurse
    Write-Host "Removed old junction"
}

$target = 'C:\Users\우유엘\AppData\Local\Android\Sdk'
New-Item -ItemType Junction -Path 'C:\android-sdk' -Target $target
Write-Host "Created junction: C:\android-sdk -> $target"

# Verify
$item = Get-Item 'C:\android-sdk' -Force
Write-Host "Junction target: $($item.Target)"
Write-Host "Platforms exists: $(Test-Path 'C:\android-sdk\platforms')"
