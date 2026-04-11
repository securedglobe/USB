# USB

Console tool that lists USB storage devices from the Windows registry and mounted volumes.

## Unit tests

`Tests\USB.Tests` is a Visual Studio C++ unit-test project. It exercises drive-letter and serial text helpers (`ToLowerString`, `NormalizeLoose`, `TrimString`, `TrimDeviceText`, `ExtractBaseSerial`) without enumerating live USB hardware.

```powershell
msbuild USB.sln /p:Configuration=Release /p:Platform=x64 /t:USB.Tests
vstest.console Tests\bin\x64\Release\USB.Tests.dll
```
