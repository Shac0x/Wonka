# Wonka 🍫

<h1 align="center">
  <img src="Logo.png" alt="Wonka Logo" width=300>
</h1>

> *"We are the music makers, and we are the dreamers of dreams."* - Willy Wonka

**Wonka** is a sweet Windows tool that extracts Kerberos tickets from the Local Security Authority (LSA) cache. Like finding a ticket, but for security research and penetration testing! 🎫

---

## ✨ Features

- 🔐 **System Impersonation** - Automatically becomes SYSTEM to access LSA
- 📋 **Session Discovery** - Finds all active logon sessions
- 🎟️ **Ticket Extraction** - Retrieves detailed Kerberos ticket information
- 📦 **Base64 Output** - Ready-to-use ticket format

## 🚀 Quick Start

### Requirements
- Windows machine
- Administrator privileges
- .NET 7.0+ (for building)

### Installation

**Option 1: Build Single Executable (Recommended)**
```powershell
dotnet publish -c Release -r win-x64 --self-contained true /p:PublishSingleFile=true
```

**Option 2: Simple Build**
```powershell
dotnet build --configuration Release
```

### Usage

```powershell
# Run as Administrator
.\Wonka.exe
```

## 📖 Sample Output

```
[+] Starting Kerberos ticket extraction process...
[+] Successfully impersonated as SYSTEM
[+] Logon sessions found: 15

[+] User: charlie.bucket@CHOCOLATE.FACTORY
[+] Tickets found: 3

-----------------------------------------------------------------------
Username = charlie.bucket
DnsDomainName = chocolate.factory
StartTime ---> 10/21/2025 10:30:15 AM
EndTime ---> 10/21/2025 8:30:15 PM
Server Name ---> krbtgt/CHOCOLATE.FACTORY
Ticket b64 ---> YIIFgjCCBX6gAwIBBaEDAgEWooIEhjCCBIJhggR+MII...
-----------------------------------------------------------------------
```

## 🏗️ Project Structure

```
wonka/
├── Program.cs      # Main ticket extraction logic
├── winapi.cs       # Windows API definitions
├── Config.cs       # Configuration and logging
└── wonka.csproj    # Project file
```

## 🔧 Technical Details

### Core APIs Used
- `OpenProcessToken` - Process token access
- `LsaRegisterLogonProcess` - LSA registration
- `LsaEnumerateLogonSessions` - Session enumeration
- `LsaCallAuthenticationPackage` - Kerberos communication

### How It Works
1. Impersonates SYSTEM via winlogon process token
2. Registers with Local Security Authority
3. Enumerates all logon sessions
4. Extracts Kerberos tickets from each session
5. Outputs tickets in Base64 format

## 🛠️ Troubleshooting

| Issue | Solution |
|-------|----------|
| "Could not impersonate as SYSTEM" | Run as Administrator |
| "Could not initialize LSA" | Check Windows compatibility |
| "No tickets found" | Ensure Kerberos is in use (`klist`) |

## ⚠️ Legal Notice

> *"A little nonsense now and then is relished by the wisest men."*

This tool is for **authorized security research and testing only**. Like Wonka's factory, enter only with permission! 🏭

**Use responsibly:**
- ✅ Security research and education
- ✅ Authorized penetration testing  
- ✅ System administration
- ❌ Unauthorized access to systems

## 🍫 About

Created for security professionals who need to extract Kerberos tickets as sweet as Wonka's chocolate. Remember: with great power comes great responsibility!

---

*"So shines a good deed in a weary world."* 🌟
