#include "pch.h"

std::wstring ToLowerString(const std::wstring& value);

std::wstring NormalizeLoose(const std::wstring& value);

std::wstring TrimString(const std::wstring& value);

std::wstring TrimDeviceText(const std::wstring& value);

std::wstring ExtractBaseSerial(const std::wstring& serial);

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

TEST_CLASS(UsbTextHelperTests)

    {

        public :

            TEST_METHOD(ToLowerStringLowersAsciiLetters)

                {

                    Assert::AreEqual(L"abc-usb", ToLowerString(L"AbC-USB").c_str());

Assert::IsTrue(ToLowerString(L"").empty());
}

TEST_METHOD(NormalizeLooseKeepsLowercaseAlphanumericOnly)

{

    Assert::AreEqual(L"sandiskcruzer123", NormalizeLoose(L"SanDisk Cruzer-123").c_str());

    Assert::IsTrue(NormalizeLoose(L"---").empty());
}

TEST_METHOD(TrimStringRemovesLeadingAndTrailingWhitespace)

{

    Assert::AreEqual(L"inner", TrimString(L"  inner \t").c_str());

    Assert::IsTrue(TrimString(L"   ").empty());
}

TEST_METHOD(TrimDeviceTextDropsPrefixBeforeSemicolon)

{

    Assert::AreEqual(L"Cruzer Blade", TrimDeviceText(L"USBSTOR; Cruzer Blade").c_str());

    Assert::AreEqual(L"plain", TrimDeviceText(L"plain").c_str());
}

TEST_METHOD(ExtractBaseSerialStopsAtAmpersand)

{

    Assert::AreEqual(L"ABC123", ExtractBaseSerial(L"ABC123&0").c_str());

    Assert::AreEqual(L"NOSPLIT", ExtractBaseSerial(L"NOSPLIT").c_str());

    Assert::IsTrue(ExtractBaseSerial(L"").empty());
}
}
;
