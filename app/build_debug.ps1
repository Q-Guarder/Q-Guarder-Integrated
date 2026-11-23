# Build script - bypasses Korean path issues
$env:JAVA_TOOL_OPTIONS = "-Dfile.encoding=UTF-8"
$env:ANDROID_HOME = "C:\android-sdk"
$env:ANDROID_SDK_ROOT = "C:\android-sdk"

Set-Location "Q:\"
.\gradlew.bat assembleDebug 2>&1
