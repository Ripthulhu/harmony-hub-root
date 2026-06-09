param(
    [string]$VendorId = "046D",
    [string]$ProductId = "C129",
    [string]$OutFile = "artifacts\myharmony-msi\hid_probe.json"
)

$ErrorActionPreference = "Stop"

$source = @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public sealed class HarmonyHidDeviceInfo {
    public string DevicePath { get; set; }
    public bool Opened { get; set; }
    public int LastError { get; set; }
    public bool AttributesOk { get; set; }
    public ushort VendorId { get; set; }
    public ushort ProductId { get; set; }
    public ushort VersionNumber { get; set; }
    public bool CapsOk { get; set; }
    public int HidPStatus { get; set; }
    public ushort UsagePage { get; set; }
    public ushort Usage { get; set; }
    public ushort InputReportByteLength { get; set; }
    public ushort OutputReportByteLength { get; set; }
    public ushort FeatureReportByteLength { get; set; }
    public ushort NumberInputValueCaps { get; set; }
    public ushort NumberOutputValueCaps { get; set; }
    public ushort NumberFeatureValueCaps { get; set; }
}

public static class HarmonyHidProbeNative {
    private const int DIGCF_PRESENT = 0x00000002;
    private const int DIGCF_DEVICEINTERFACE = 0x00000010;
    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint FILE_SHARE_WRITE = 0x00000002;
    private const uint OPEN_EXISTING = 3;

    [StructLayout(LayoutKind.Sequential)]
    private struct SP_DEVICE_INTERFACE_DATA {
        public int cbSize;
        public Guid InterfaceClassGuid;
        public int Flags;
        public IntPtr Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct HIDD_ATTRIBUTES {
        public int Size;
        public ushort VendorID;
        public ushort ProductID;
        public ushort VersionNumber;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct HIDP_CAPS {
        public ushort Usage;
        public ushort UsagePage;
        public ushort InputReportByteLength;
        public ushort OutputReportByteLength;
        public ushort FeatureReportByteLength;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 17)]
        public ushort[] Reserved;
        public ushort NumberLinkCollectionNodes;
        public ushort NumberInputButtonCaps;
        public ushort NumberInputValueCaps;
        public ushort NumberInputDataIndices;
        public ushort NumberOutputButtonCaps;
        public ushort NumberOutputValueCaps;
        public ushort NumberOutputDataIndices;
        public ushort NumberFeatureButtonCaps;
        public ushort NumberFeatureValueCaps;
        public ushort NumberFeatureDataIndices;
    }

    [DllImport("hid.dll", SetLastError = true)]
    private static extern void HidD_GetHidGuid(out Guid hidGuid);

    [DllImport("setupapi.dll", SetLastError = true)]
    private static extern IntPtr SetupDiGetClassDevs(
        ref Guid ClassGuid,
        IntPtr Enumerator,
        IntPtr hwndParent,
        int Flags);

    [DllImport("setupapi.dll", SetLastError = true)]
    private static extern bool SetupDiEnumDeviceInterfaces(
        IntPtr DeviceInfoSet,
        IntPtr DeviceInfoData,
        ref Guid InterfaceClassGuid,
        int MemberIndex,
        ref SP_DEVICE_INTERFACE_DATA DeviceInterfaceData);

    [DllImport("setupapi.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern bool SetupDiGetDeviceInterfaceDetail(
        IntPtr DeviceInfoSet,
        ref SP_DEVICE_INTERFACE_DATA DeviceInterfaceData,
        IntPtr DeviceInterfaceDetailData,
        int DeviceInterfaceDetailDataSize,
        out int RequiredSize,
        IntPtr DeviceInfoData);

    [DllImport("setupapi.dll", SetLastError = true)]
    private static extern bool SetupDiDestroyDeviceInfoList(IntPtr DeviceInfoSet);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern SafeFileHandle CreateFile(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("hid.dll", SetLastError = true)]
    private static extern bool HidD_GetAttributes(SafeFileHandle HidDeviceObject, ref HIDD_ATTRIBUTES Attributes);

    [DllImport("hid.dll", SetLastError = true)]
    private static extern bool HidD_GetPreparsedData(SafeFileHandle HidDeviceObject, out IntPtr PreparsedData);

    [DllImport("hid.dll", SetLastError = true)]
    private static extern bool HidD_FreePreparsedData(IntPtr PreparsedData);

    [DllImport("hid.dll")]
    private static extern int HidP_GetCaps(IntPtr PreparsedData, out HIDP_CAPS Capabilities);

    public static HarmonyHidDeviceInfo[] Enumerate(string vendorId, string productId) {
        string needle = "vid_" + vendorId.ToLowerInvariant() + "&pid_" + productId.ToLowerInvariant();
        var results = new List<HarmonyHidDeviceInfo>();
        Guid hidGuid;
        HidD_GetHidGuid(out hidGuid);

        IntPtr set = SetupDiGetClassDevs(ref hidGuid, IntPtr.Zero, IntPtr.Zero, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
        if (set == IntPtr.Zero || set.ToInt64() == -1) {
            throw new InvalidOperationException("SetupDiGetClassDevs failed: " + Marshal.GetLastWin32Error());
        }

        try {
            for (int i = 0; ; i++) {
                var data = new SP_DEVICE_INTERFACE_DATA();
                data.cbSize = Marshal.SizeOf(typeof(SP_DEVICE_INTERFACE_DATA));
                if (!SetupDiEnumDeviceInterfaces(set, IntPtr.Zero, ref hidGuid, i, ref data)) {
                    int err = Marshal.GetLastWin32Error();
                    if (err == 259) break; // ERROR_NO_MORE_ITEMS
                    throw new InvalidOperationException("SetupDiEnumDeviceInterfaces failed: " + err);
                }

                int required;
                SetupDiGetDeviceInterfaceDetail(set, ref data, IntPtr.Zero, 0, out required, IntPtr.Zero);
                IntPtr detail = Marshal.AllocHGlobal(required);
                try {
                    Marshal.WriteInt32(detail, IntPtr.Size == 8 ? 8 : 6);
                    if (!SetupDiGetDeviceInterfaceDetail(set, ref data, detail, required, out required, IntPtr.Zero)) {
                        continue;
                    }

                    string path = Marshal.PtrToStringAuto(IntPtr.Add(detail, 4));
                    if (path == null || path.ToLowerInvariant().IndexOf(needle, StringComparison.Ordinal) < 0) {
                        continue;
                    }

                    var info = new HarmonyHidDeviceInfo();
                    info.DevicePath = path;

                    using (SafeFileHandle handle = CreateFile(path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero)) {
                        info.Opened = handle != null && !handle.IsInvalid;
                        info.LastError = Marshal.GetLastWin32Error();
                        if (info.Opened) {
                            var attrs = new HIDD_ATTRIBUTES();
                            attrs.Size = Marshal.SizeOf(typeof(HIDD_ATTRIBUTES));
                            info.AttributesOk = HidD_GetAttributes(handle, ref attrs);
                            info.VendorId = attrs.VendorID;
                            info.ProductId = attrs.ProductID;
                            info.VersionNumber = attrs.VersionNumber;

                            IntPtr prep;
                            if (HidD_GetPreparsedData(handle, out prep)) {
                                try {
                                    HIDP_CAPS caps;
                                    info.HidPStatus = HidP_GetCaps(prep, out caps);
                                    info.CapsOk = info.HidPStatus == 0x00110000;
                                    info.UsagePage = caps.UsagePage;
                                    info.Usage = caps.Usage;
                                    info.InputReportByteLength = caps.InputReportByteLength;
                                    info.OutputReportByteLength = caps.OutputReportByteLength;
                                    info.FeatureReportByteLength = caps.FeatureReportByteLength;
                                    info.NumberInputValueCaps = caps.NumberInputValueCaps;
                                    info.NumberOutputValueCaps = caps.NumberOutputValueCaps;
                                    info.NumberFeatureValueCaps = caps.NumberFeatureValueCaps;
                                } finally {
                                    HidD_FreePreparsedData(prep);
                                }
                            }
                        }
                    }

                    results.Add(info);
                } finally {
                    Marshal.FreeHGlobal(detail);
                }
            }
        } finally {
            SetupDiDestroyDeviceInfoList(set);
        }

        return results.ToArray();
    }
}
"@

Add-Type -TypeDefinition $source -Language CSharp

$devices = [HarmonyHidProbeNative]::Enumerate($VendorId, $ProductId)

$outDir = Split-Path -Parent $OutFile
if ($outDir -and -not (Test-Path $outDir)) {
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null
}

$json = ConvertTo-Json -InputObject @($devices) -Depth 5
if ([string]::IsNullOrWhiteSpace($json)) {
    $json = "[]"
}
$json | Set-Content -Encoding UTF8 -Path $OutFile

if ($devices) {
    $devices |
        Select-Object VendorId, ProductId, VersionNumber, UsagePage, Usage, InputReportByteLength, OutputReportByteLength, FeatureReportByteLength, Opened, CapsOk, DevicePath |
        Format-List
    Write-Host "Wrote $OutFile"
} else {
    Write-Host "No matching HID interfaces found for VID_$VendorId PID_$ProductId."
}
