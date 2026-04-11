// USB forensics
// Shows which USB drive was last connected and when

#if defined(__has_include)
#if __has_include("pch.h")
#include "pch.h"
#endif
#endif

#include <windows.h>
#include <winreg.h>
#include <cstdio>
#include <cstdarg>
#include <cwchar>
#include <cwctype>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <algorithm>

struct MountedDeviceEntry
{
    std::wstring valueName;
    std::vector<BYTE> data;
    std::wstring decodedText;
};

struct UsbDriveRecord
{
    std::wstring registryTypeKey;
    std::wstring registryInstanceKey;
    std::wstring instanceId;
    std::wstring serialNumber;
    std::wstring parentIdPrefix;
    std::wstring friendlyName;
    std::wstring driveLetter;
    std::wstring volumeLabel;
    FILETIME    lastWriteTime{};
};

void WriteLogFile(const wchar_t* format, ...)
{
    va_list args;
    va_start(args, format);
    vwprintf_s(format, args);
    va_end(args);
}

std::wstring ToLowerString(const std::wstring& value)
{
    std::wstring result = value;

    for (wchar_t& ch : result)
    {
        ch = (wchar_t)towlower(ch);
    }

    return result;
}

std::wstring NormalizeLoose(const std::wstring& value)
{
    std::wstring result;
    result.reserve(value.size());

    for (wchar_t ch : value)
    {
        if (iswalnum(ch))
        {
            result.push_back((wchar_t)towlower(ch));
        }
    }

    return result;
}

std::wstring TrimDeviceText(const std::wstring& value)
{
    if (value.empty())
    {
        return value;
    }

    std::wstring result = value;

    size_t semicolonPos = result.find(L';');
    if (semicolonPos != std::wstring::npos && semicolonPos + 1 < result.size())
    {
        result = result.substr(semicolonPos + 1);
    }

    while (!result.empty() && iswspace(result.front()))
    {
        result.erase(result.begin());
    }

    while (!result.empty() && iswspace(result.back()))
    {
        result.pop_back();
    }

    return result;
}

bool QueryRegistryString(HKEY hKey, const wchar_t* valueName, std::wstring& output)
{
    output.clear();

    DWORD type = 0;
    DWORD cbData = 0;

    LONG status = RegQueryValueExW(
        hKey,
        valueName,
        nullptr,
        &type,
        nullptr,
        &cbData);

    if (status != ERROR_SUCCESS)
    {
        return false;
    }

    if (type != REG_SZ && type != REG_EXPAND_SZ)
    {
        return false;
    }

    std::vector<wchar_t> buffer((cbData / sizeof(wchar_t)) + 2, L'\0');

    status = RegQueryValueExW(
        hKey,
        valueName,
        nullptr,
        &type,
        reinterpret_cast<LPBYTE>(buffer.data()),
        &cbData);

    if (status != ERROR_SUCCESS)
    {
        return false;
    }

    output.assign(buffer.data());
    return true;
}

bool QueryRegistryBinary(HKEY hKey, const wchar_t* valueName, std::vector<BYTE>& output)
{
    output.clear();

    DWORD type = 0;
    DWORD cbData = 0;

    LONG status = RegQueryValueExW(
        hKey,
        valueName,
        nullptr,
        &type,
        nullptr,
        &cbData);

    if (status != ERROR_SUCCESS)
    {
        return false;
    }

    if (type != REG_BINARY)
    {
        return false;
    }

    output.resize(cbData);

    status = RegQueryValueExW(
        hKey,
        valueName,
        nullptr,
        &type,
        output.data(),
        &cbData);

    if (status != ERROR_SUCCESS)
    {
        output.clear();
        return false;
    }

    return true;
}

std::wstring FileTimeToLocalString(const FILETIME& ft)
{
    SYSTEMTIME stUtc{};
    SYSTEMTIME stLocal{};

    if (!FileTimeToSystemTime(&ft, &stUtc))
    {
        return L"(unknown time)";
    }

    if (!SystemTimeToTzSpecificLocalTime(nullptr, &stUtc, &stLocal))
    {
        stLocal = stUtc;
    }

    wchar_t buffer[128]{};
    swprintf_s(
        buffer,
        L"%04u-%02u-%02u %02u:%02u:%02u",
        stLocal.wYear,
        stLocal.wMonth,
        stLocal.wDay,
        stLocal.wHour,
        stLocal.wMinute,
        stLocal.wSecond);

    return buffer;
}

std::wstring DecodeMountedDeviceBinary(const std::vector<BYTE>& data)
{
    std::wstring unicodeText;
    std::wstring asciiText;

    if (data.size() >= sizeof(wchar_t))
    {
        size_t wcharCount = data.size() / sizeof(wchar_t);
        const wchar_t* wptr = reinterpret_cast<const wchar_t*>(data.data());

        unicodeText.reserve(wcharCount);

        for (size_t i = 0; i < wcharCount; ++i)
        {
            wchar_t ch = wptr[i];

            if (ch == L'\0')
            {
                unicodeText.push_back(L' ');
                continue;
            }

            if (ch >= 32 && ch < 127)
            {
                unicodeText.push_back((wchar_t)towlower(ch));
            }
            else if (iswprint(ch))
            {
                unicodeText.push_back((wchar_t)towlower(ch));
            }
            else
            {
                unicodeText.push_back(L' ');
            }
        }
    }

    asciiText.reserve(data.size());

    for (BYTE b : data)
    {
        if (b >= 32 && b < 127)
        {
            asciiText.push_back((wchar_t)towlower((wchar_t)b));
        }
        else
        {
            asciiText.push_back(L' ');
        }
    }

    return unicodeText + L" " + asciiText;
}

bool DataEquals(const std::vector<BYTE>& a, const std::vector<BYTE>& b)
{
    if (a.size() != b.size())
    {
        return false;
    }

    if (a.empty())
    {
        return true;
    }

    return memcmp(a.data(), b.data(), a.size()) == 0;
}

std::vector<MountedDeviceEntry> LoadMountedDevices()
{
    std::vector<MountedDeviceEntry> entries;

    HKEY hKey = nullptr;
    LONG status = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\MountedDevices",
        0,
        KEY_READ,
        &hKey);

    if (status != ERROR_SUCCESS)
    {
        return entries;
    }

    DWORD valueCount = 0;
    DWORD maxValueNameLen = 0;
    DWORD maxValueLen = 0;

    status = RegQueryInfoKeyW(
        hKey,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        &valueCount,
        &maxValueNameLen,
        &maxValueLen,
        nullptr,
        nullptr);

    if (status != ERROR_SUCCESS)
    {
        RegCloseKey(hKey);
        return entries;
    }

    std::vector<wchar_t> nameBuffer(maxValueNameLen + 2, L'\0');
    std::vector<BYTE> dataBuffer(maxValueLen + 2, 0);

    for (DWORD index = 0; index < valueCount; ++index)
    {
        DWORD nameLen = (DWORD)nameBuffer.size();
        DWORD dataLen = (DWORD)dataBuffer.size();
        DWORD type = 0;

        LONG enumStatus = RegEnumValueW(
            hKey,
            index,
            nameBuffer.data(),
            &nameLen,
            nullptr,
            &type,
            dataBuffer.data(),
            &dataLen);

        if (enumStatus != ERROR_SUCCESS)
        {
            continue;
        }

        if (type != REG_BINARY)
        {
            continue;
        }

        MountedDeviceEntry entry;
        entry.valueName.assign(nameBuffer.data(), nameLen);
        entry.data.assign(dataBuffer.begin(), dataBuffer.begin() + dataLen);
        entry.decodedText = DecodeMountedDeviceBinary(entry.data);
        entries.push_back(std::move(entry));
    }

    RegCloseKey(hKey);
    return entries;
}

std::wstring FindDriveLetterFromMountedDevices(
    const std::vector<MountedDeviceEntry>& mountedDevices,
    const std::wstring& instanceId,
    const std::wstring& serialNumber,
    const std::wstring& parentIdPrefix,
    const std::wstring& friendlyName)
{
    std::vector<std::wstring> exactNeedles;
    std::vector<std::wstring> looseNeedles;

    if (!instanceId.empty())
    {
        exactNeedles.push_back(ToLowerString(instanceId));
        looseNeedles.push_back(NormalizeLoose(instanceId));
    }

    if (!serialNumber.empty())
    {
        exactNeedles.push_back(ToLowerString(serialNumber));
        looseNeedles.push_back(NormalizeLoose(serialNumber));
    }

    if (!parentIdPrefix.empty())
    {
        exactNeedles.push_back(ToLowerString(parentIdPrefix));
        looseNeedles.push_back(NormalizeLoose(parentIdPrefix));
    }

    if (!friendlyName.empty())
    {
        looseNeedles.push_back(NormalizeLoose(friendlyName));
    }

    const MountedDeviceEntry* matchedEntry = nullptr;

    for (const MountedDeviceEntry& entry : mountedDevices)
    {
        bool found = false;
        const std::wstring haystackExact = ToLowerString(entry.decodedText);
        const std::wstring haystackLoose = NormalizeLoose(entry.decodedText);

        for (const std::wstring& needle : exactNeedles)
        {
            if (!needle.empty() && haystackExact.find(needle) != std::wstring::npos)
            {
                found = true;
                break;
            }
        }

        if (!found)
        {
            for (const std::wstring& needle : looseNeedles)
            {
                if (!needle.empty() && haystackLoose.find(needle) != std::wstring::npos)
                {
                    found = true;
                    break;
                }
            }
        }

        if (found)
        {
            matchedEntry = &entry;
            break;
        }
    }

    if (matchedEntry == nullptr)
    {
        return L"";
    }

    const std::wstring prefix = L"\\DosDevices\\";

    if (matchedEntry->valueName.rfind(prefix, 0) == 0 && matchedEntry->valueName.size() >= prefix.size() + 2)
    {
        wchar_t driveLetter = matchedEntry->valueName[prefix.size()];
        if (driveLetter >= L'A' && driveLetter <= L'Z')
        {
            std::wstring result;
            result.push_back(driveLetter);
            result.push_back(L':');
            return result;
        }
    }

    for (const MountedDeviceEntry& entry : mountedDevices)
    {
        if (!DataEquals(entry.data, matchedEntry->data))
        {
            continue;
        }

        if (entry.valueName.rfind(prefix, 0) == 0 && entry.valueName.size() >= prefix.size() + 2)
        {
            wchar_t driveLetter = entry.valueName[prefix.size()];
            if (driveLetter >= L'A' && driveLetter <= L'Z')
            {
                std::wstring result;
                result.push_back(driveLetter);
                result.push_back(L':');
                return result;
            }
        }
    }

    return L"";
}

std::wstring GetVolumeLabelForDriveLetter(const std::wstring& driveLetter)
{
    if (driveLetter.size() != 2 || driveLetter[1] != L':')
    {
        return L"";
    }

    wchar_t rootPath[4]{};
    rootPath[0] = driveLetter[0];
    rootPath[1] = L':';
    rootPath[2] = L'\\';
    rootPath[3] = L'\0';

    DWORD attributes = GetFileAttributesW(rootPath);
    if (attributes == INVALID_FILE_ATTRIBUTES)
    {
        return L"";
    }

    wchar_t volumeName[MAX_PATH]{};
    if (!GetVolumeInformationW(
        rootPath,
        volumeName,
        (DWORD)_countof(volumeName),
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        0))
    {
        return L"";
    }

    return volumeName;
}

std::vector<UsbDriveRecord> EnumerateUsbStorHistory()
{
    std::vector<UsbDriveRecord> records;
    std::vector<MountedDeviceEntry> mountedDevices = LoadMountedDevices();

    HKEY hRoot = nullptr;
    LONG status = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Enum\\USBSTOR",
        0,
        KEY_READ,
        &hRoot);

    if (status != ERROR_SUCCESS)
    {
        WriteLogFile(L"Unable to open USBSTOR registry key.\n");
        return records;
    }

    DWORD typeKeyCount = 0;
    DWORD maxTypeKeyLen = 0;

    status = RegQueryInfoKeyW(
        hRoot,
        nullptr,
        nullptr,
        nullptr,
        &typeKeyCount,
        &maxTypeKeyLen,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr);

    if (status != ERROR_SUCCESS)
    {
        RegCloseKey(hRoot);
        WriteLogFile(L"Unable to query USBSTOR registry key info.\n");
        return records;
    }

    std::vector<wchar_t> typeNameBuffer(maxTypeKeyLen + 2, L'\0');

    for (DWORD typeIndex = 0; typeIndex < typeKeyCount; ++typeIndex)
    {
        DWORD typeNameLen = (DWORD)typeNameBuffer.size();

        LONG enumTypeStatus = RegEnumKeyExW(
            hRoot,
            typeIndex,
            typeNameBuffer.data(),
            &typeNameLen,
            nullptr,
            nullptr,
            nullptr,
            nullptr);

        if (enumTypeStatus != ERROR_SUCCESS)
        {
            continue;
        }

        std::wstring typeKeyName(typeNameBuffer.data(), typeNameLen);

        HKEY hTypeKey = nullptr;
        status = RegOpenKeyExW(
            hRoot,
            typeKeyName.c_str(),
            0,
            KEY_READ,
            &hTypeKey);

        if (status != ERROR_SUCCESS)
        {
            continue;
        }

        DWORD instanceCount = 0;
        DWORD maxInstanceLen = 0;

        status = RegQueryInfoKeyW(
            hTypeKey,
            nullptr,
            nullptr,
            nullptr,
            &instanceCount,
            &maxInstanceLen,
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            nullptr);

        if (status != ERROR_SUCCESS)
        {
            RegCloseKey(hTypeKey);
            continue;
        }

        std::vector<wchar_t> instanceBuffer(maxInstanceLen + 2, L'\0');

        for (DWORD instanceIndex = 0; instanceIndex < instanceCount; ++instanceIndex)
        {
            DWORD instanceLen = (DWORD)instanceBuffer.size();

            LONG enumInstanceStatus = RegEnumKeyExW(
                hTypeKey,
                instanceIndex,
                instanceBuffer.data(),
                &instanceLen,
                nullptr,
                nullptr,
                nullptr,
                nullptr);

            if (enumInstanceStatus != ERROR_SUCCESS)
            {
                continue;
            }

            std::wstring instanceKeyName(instanceBuffer.data(), instanceLen);

            HKEY hInstanceKey = nullptr;
            status = RegOpenKeyExW(
                hTypeKey,
                instanceKeyName.c_str(),
                0,
                KEY_READ,
                &hInstanceKey);

            if (status != ERROR_SUCCESS)
            {
                continue;
            }

            UsbDriveRecord record;
            record.registryTypeKey = typeKeyName;
            record.registryInstanceKey = instanceKeyName;
            record.instanceId = L"USBSTOR\\" + typeKeyName + L"\\" + instanceKeyName;
            record.serialNumber = instanceKeyName;

            std::wstring value;

            if (QueryRegistryString(hInstanceKey, L"FriendlyName", value))
            {
                record.friendlyName = TrimDeviceText(value);
            }

            if (record.friendlyName.empty() && QueryRegistryString(hInstanceKey, L"DeviceDesc", value))
            {
                record.friendlyName = TrimDeviceText(value);
            }

            if (QueryRegistryString(hInstanceKey, L"ParentIdPrefix", value))
            {
                record.parentIdPrefix = TrimDeviceText(value);
            }

            DWORD subKeyCount = 0;
            DWORD maxSubKeyLen = 0;

            status = RegQueryInfoKeyW(
                hInstanceKey,
                nullptr,
                nullptr,
                nullptr,
                &subKeyCount,
                &maxSubKeyLen,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                &record.lastWriteTime);

            if (status != ERROR_SUCCESS)
            {
                ZeroMemory(&record.lastWriteTime, sizeof(record.lastWriteTime));
            }

            record.driveLetter = FindDriveLetterFromMountedDevices(
                mountedDevices,
                record.instanceId,
                record.serialNumber,
                record.parentIdPrefix,
                record.friendlyName);

            if (!record.driveLetter.empty())
            {
                record.volumeLabel = GetVolumeLabelForDriveLetter(record.driveLetter);
            }

            records.push_back(std::move(record));
            RegCloseKey(hInstanceKey);
        }

        RegCloseKey(hTypeKey);
    }

    RegCloseKey(hRoot);

    std::sort(
        records.begin(),
        records.end(),
        [](const UsbDriveRecord& a, const UsbDriveRecord& b)
        {
            ULARGE_INTEGER ia{};
            ia.LowPart = a.lastWriteTime.dwLowDateTime;
            ia.HighPart = a.lastWriteTime.dwHighDateTime;

            ULARGE_INTEGER ib{};
            ib.LowPart = b.lastWriteTime.dwLowDateTime;
            ib.HighPart = b.lastWriteTime.dwHighDateTime;

            return ia.QuadPart > ib.QuadPart;
        });

    return records;
}

int wmain()
{
    WriteLogFile(L"USB forensics\nBy Secured Globe, Inc.\nDeveloped by Michael Haephrati\nShows which USB drive was last connected and when\n\n");
    WriteLogFile(L"Last connected USB storage drives\n");
    WriteLogFile(L"================================\n\n");

    std::vector<UsbDriveRecord> records = EnumerateUsbStorHistory();

    if (records.empty())
    {
        WriteLogFile(L"No USB storage history was found.\n");
        return 0;
    }

    std::set<std::wstring> seen;
    int printedCount = 0;

    for (const UsbDriveRecord& record : records)
    {
        std::wstring dedupeKey =
            ToLowerString(record.registryTypeKey) + L"|" +
            ToLowerString(record.registryInstanceKey);

        if (seen.find(dedupeKey) != seen.end())
        {
            continue;
        }

        seen.insert(dedupeKey);
        ++printedCount;

        std::wstring displayName = record.friendlyName;
        if (displayName.empty())
        {
            displayName = record.registryTypeKey;
        }

        std::wstring driveDisplay = record.driveLetter;
        if (driveDisplay.empty())
        {
            driveDisplay = L"(unknown)";
        }

        std::wstring timeDisplay = FileTimeToLocalString(record.lastWriteTime);

        WriteLogFile(L"%d)\n", printedCount);
        WriteLogFile(L"   Last Seen : %s\n", timeDisplay.c_str());
        WriteLogFile(L"   Drive     : %s\n", driveDisplay.c_str());

        if (!record.volumeLabel.empty())
        {
            WriteLogFile(L"   Label     : %s\n", record.volumeLabel.c_str());
        }

        WriteLogFile(L"   Name      : %s\n", displayName.c_str());

        if (!record.serialNumber.empty())
        {
            WriteLogFile(L"   Serial    : %s\n", record.serialNumber.c_str());
        }

        WriteLogFile(L"\n");
    }

    return 0;
}