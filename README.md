# Wonka 🍫

<h1 align="center">
  <img src="Logo.png" alt="Wonka Logo" width=300>
</h1>

> *"We are the music makers, and we are the dreamers of dreams."* - Willy Wonka

**Wonka** is a sweet Windows tool that extracts Kerberos tickets from the Local Security Authority (LSA) cache. Like finding a ticket, but for security research and penetration testing! 🎫

---

## ✨ Features

- 🔐 **System Impersonation** - Automatically becomes SYSTEM to access LSA (when running elevated)
- 👤 **Privilege-aware** - Standard users dump only their *own* session via an untrusted LSA connection; no SYSTEM impersonation required
- 📋 **Session Discovery** - Finds all active logon sessions
- 🗂️ **List mode** - List users and ticket metadata only, without extracting the base64 blobs
- 🎯 **Single-ticket dump** - Target one ticket by LUID and/or service name
- 🎟️ **Ticket Extraction** - Retrieves detailed Kerberos ticket information
- 📦 **Base64 Output** - Ready-to-use ticket format

## 🚀 Quick Start

### Requirements
- Windows machine
- Administrator privileges *for dumping every session* (a standard user can still dump their own tickets)
- .NET 8.0+ (for building)

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
.\Wonka.exe <list|dump> [/luid:<luid>] [/service:<name>]
```

> Running `.\Wonka.exe` with **no arguments** (or `-h`) prints the help — you must pass `dump` or `list` explicitly to do anything.

Wonka adapts to the privileges it is running with:

- **Administrator** → processes every logon session on the host.
- **Standard user** → processes only the current user's tickets (untrusted LSA connection, no SYSTEM impersonation).

#### Modes & options

| Command | What it does |
|---------|--------------|
| `.\Wonka.exe` *(no args)* | Show help. |
| `.\Wonka.exe dump` | Extract tickets (base64) for every accessible session. |
| `.\Wonka.exe list` | List users and ticket **metadata only** — no base64 is extracted. |
| `.\Wonka.exe dump /luid:<luid>` | Dump only the session with the given LUID (hex `0x3e7` or decimal `999`). |
| `.\Wonka.exe dump /service:<name>` | Dump only tickets whose server name contains `<name>` (e.g. `krbtgt`, `cifs/host.domain`). |
| `.\Wonka.exe dump /luid:0x3e7 /service:krbtgt` | Combine filters to dump a **single** ticket. |
| `.\Wonka.exe -h` | Show help. |

> `/luid` and `/service` are dump-only filters; combining them with `list` is rejected.

#### Examples

```powershell
# Show help (also shown when run with no arguments)
.\Wonka.exe -h

# Dump every accessible ticket (all sessions if elevated, otherwise just yours)
.\Wonka.exe dump

# Just enumerate who has tickets, without pulling the blobs (admin)
.\Wonka.exe list

# Pull a single krbtgt ticket (TGT) for one logon session
.\Wonka.exe dump /luid:0x3e7 /service:krbtgt
```

## 📖 Sample Output

```
Starting Kerberos ticket extraction process...
[+] Running with administrative privileges
[+] Successfully impersonated as SYSTEM
[+] Logon sessions found: 15

[+] User: charlie.bucket@CHOCOLATE.FACTORY
[+] LogonId: 0x3e7 | Tickets found: 3

-----------------------------------------------------------------------
Username = charlie.bucket
DnsDomainName = chocolate.factory
StartTime ---> 10/21/2025 10:30:15 AM
EndTime ---> 10/21/2025 8:30:15 PM
Server Name ---> krbtgt/CHOCOLATE.FACTORY
Ticket b64 ---> YIIFgjCCBX6gAwIBBaEDAgEWooIEhjCCBIJhggR+MII...
-----------------------------------------------------------------------
```

> In `list` mode the output is identical **except** the `Ticket b64` / `EncType` lines are omitted — you get the metadata without the extractable ticket blob.

## 🏗️ Project Structure

```
Wonka/
├── Program.cs      # CLI parsing + ticket extraction logic
├── Winapi.cs       # Windows API definitions
└── Wonka.csproj    # Project file
```

## 🔧 Technical Details

### Core APIs Used
- `OpenProcessToken` / `DuplicateTokenEx` / `ImpersonateLoggedOnUser` / `RevertToSelf` - SYSTEM impersonation (admin path)
- `LsaRegisterLogonProcess` - Privileged LSA registration (admin path)
- `LsaConnectUntrusted` - Unprivileged LSA connection for the current user (standard-user path)
- `LsaEnumerateLogonSessions` - Session enumeration
- `LsaCallAuthenticationPackage` - Kerberos communication

### How It Works

**Elevated (Administrator):**
1. Impersonates SYSTEM via the winlogon process token
2. Registers with the Local Security Authority (`LsaRegisterLogonProcess`)
3. Enumerates all logon sessions
4. Extracts Kerberos tickets from each session (or only those matching `/luid` / `/service`)
5. Outputs tickets in Base64 format (or metadata only in `list` mode)

**Standard user:**
1. Opens an untrusted LSA connection (`LsaConnectUntrusted`) — no impersonation needed
2. Queries the caller's own logon session (LUID `{0,0}`)
3. Extracts the current user's Kerberos tickets

## 🛠️ Troubleshooting

| Issue | Solution |
|-------|----------|
| "Could not impersonate as SYSTEM" | Run as Administrator (or run as a standard user to dump just your own tickets) |
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
