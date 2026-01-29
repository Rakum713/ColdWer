# 📁 Windows 8.1 WerFaultSecure.exe

## ⚠️ Required for DUMP Mode

The `cw-dump` command requires `WerFaultSecure.exe` from **Windows 8.1**.

>Modern Windows versions only output encrypted dumps. The Win8.1 version has the `/file` parameter for raw, unencrypted minidumps.

---

## 📥 How to Obtain

### Option 1: Windows 8.1 ISO

1. Download Windows 8.1 ISO from Microsoft
2. Mount the ISO
3. Extract from: `sources\install.wim\Windows\System32\WerFaultSecure.exe`

### Extraction Commands

##### Using 7-Zip

```bash
7z e install.wim Windows/System32/WerFaultSecure.exe
```

### Option 2: Windows 8.1 VM

1. Create a Windows 8.1 VM
2. Copy `C:\Windows\System32\WerFaultSecure.exe`

---

## 📤 Upload to Target

```bash
beacon> cd C:\Windows\Temp
beacon> upload /path/to/bin/wfs.exe
```
