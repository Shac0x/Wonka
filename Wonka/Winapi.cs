using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using System.Security.Principal;

/// <summary>
/// Windows API definitions for Kerberos ticket operations
/// </summary>
public static class win32
{
    // Token access rights
    public const uint TOKEN_QUERY = 0x0008;
    public const uint TOKEN_DUPLICATE = 0x0002;
    public const uint MAXIMUM_ALLOWED = 0x02000000;
    public const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    public const uint TOKEN_QUERY_SOURCE = 0x0010;
    public const uint TOKEN_IMPERSONATE = 0x0004;

    // Security impersonation levels
    public enum SECURITY_IMPERSONATION_LEVEL : uint
    {
        SecurityAnonymous = 0,
        SecurityIdentification = 1,
        SecurityImpersonation = 2,
        SecurityDelegation = 3
    }

    // Token types
    public enum TOKEN_TYPE : uint
    {
        TokenPrimary = 1,
        TokenImpersonation = 2
    }

    // Process and Token Functions
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool DuplicateTokenEx(
        IntPtr hExistingToken,
        uint dwDesiredAccess,
        IntPtr lpTokenAttributes,
        SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
        TOKEN_TYPE TokenType,
        out IntPtr phNewToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(
        IntPtr ProcessHandle,
        uint DesiredAccess,
        out IntPtr TokenHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    // LSA String structure
    [StructLayout(LayoutKind.Sequential)]
    public struct LSA_STRING_IN
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr buffer;
    }

    // LSA Functions
    [DllImport("secur32.dll", SetLastError = true)]
    public static extern int LsaRegisterLogonProcess(
        LSA_STRING_IN LogonProcessName, 
        out IntPtr LsaHandle, 
        out ulong SecurityMode);

    [DllImport("secur32.dll", SetLastError = false)]
    public static extern int LsaLookupAuthenticationPackage(
        [In] IntPtr LsaHandle, 
        [In] ref LSA_STRING_IN PackageName, 
        [Out] out uint AuthenticationPackage);

    [DllImport("Secur32.dll", SetLastError = false)]
    public static extern int LsaEnumerateLogonSessions(
        out uint LogonSessionCount, 
        out IntPtr LogonSessionList);

    [DllImport("secur32.dll", SetLastError = false)]
    public static extern int LsaFreeReturnBuffer([In] IntPtr buffer);

    [DllImport("Secur32.dll", SetLastError = false)]
    public static extern uint LsaGetLogonSessionData(
        IntPtr luid, 
        out IntPtr ppLogonSessionData);

    [DllImport("Secur32.dll", SetLastError = true)]
    public static extern int LsaCallAuthenticationPackage(
        IntPtr LsaHandle, 
        uint AuthenticationPackage, 
        IntPtr ProtocolSubmitBuffer, 
        int SubmitBufferLength, 
        out IntPtr ProtocolReturnBuffer, 
        out ulong ReturnBufferLength, 
        out int ProtocolStatus);

    [DllImport("secur32.dll", SetLastError = false)]
    public static extern int LsaDeregisterLogonProcess(IntPtr LsaHandle);

    // Memory Functions
    [DllImport("kernel32.dll", EntryPoint = "RtlMoveMemory", SetLastError = false)]
    public static extern void CopyMemory(IntPtr dest, IntPtr src, uint count);

    // LUID structure
    [StructLayout(LayoutKind.Sequential)]
    public struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    // Logon session data structures
    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_LOGON_SESSION_DATA
    {
        public uint size;
        public LUID LogonID;
        public LSA_STRING_IN username;
        public LSA_STRING_IN LogonDomain;
        public LSA_STRING_IN AuthenticationPackage;
        public uint logontype;
        public uint Session;
        public IntPtr PSid;
        public ulong LogonTime;
        public LSA_STRING_IN LogonServer;
        public LSA_STRING_IN DnsDomainName;
        public LSA_STRING_IN Upn;
    }

    public enum LogonType
    {
        UndefinedLogonType,
        Interactive,
        Network,
        Batch,
        Service,
        Proxy,
        Unlock,
        NetworkCleartext,
        NewCredentials,
        RemoteInteractive,
        CachedInteractive,
        CachedRemoteInteractive,
        CachedUnlock
    }

    public class LogonSessionData
    {
        public LUID LogonID;
        public string? username;
        public string? LogonDomain;
        public string? AuthenticationPackage;
        public LogonType logonType;
        public int Session;
        public SecurityIdentifier? Sid;
        public DateTime LogonTime;
        public string? LogonServer;
        public string? DnsDomainName;
        public string? Upn;
    }

    // Kerberos protocol message types
    public enum KERB_PROTOCOL_MESSAGE_TYPE
    {
        KerbDebugRequestMessage,
        KerbQueryTicketCacheMessage,
        KerbChangeMachinePasswordMessage,
        KerbVerifyPacMessage,
        KerbRetrieveTicketMessage,
        KerbUpdateAddressesMessage,
        KerbPurgeTicketCacheMessage,
        KerbChangePasswordMessage,
        KerbRetrieveEncodedTicketMessage,
        KerbDecryptDataMessage,
        KerbAddBindingCacheEntryMessage,
        KerbSetPasswordMessage,
        KerbSetPasswordExMessage,
        KerbVerifyCredentialMessage,
        KerbQueryTicketCacheExMessage,
        KerbPurgeTicketCacheExMessage,
        KerbRefreshSmartcardCredentialsMessage,
        KerbAddExtraCredentialsMessage,
        KerbQuerySupplementalCredentialsMessage,
        KerbTransferCredentialsMessage,
        KerbQueryTicketCacheEx2Message,
        KerbSubmitTicketMessage,
        KerbAddExtraCredentialsExMessage
    }

    // Kerberos structures
    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_QUERY_TKT_CACHE_REQUEST
    {
        public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
        public LUID LogonId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_QUERY_TKT_CACHE_RESPONSE
    {
        public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
        public int CountOfTickets;
        public IntPtr Tickets;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_RETRIEVE_TKT_REQUEST
    {
        public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
        public LUID LogonId;
        public UNICODE_STRING TargetName;
        public uint TicketFlags;
        public uint CacheOptions;
        public int EncryptionType;
        public SECURITY_HANDLE CredentialsHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_CRYPTO_KEY
    {
        public int KeyType;
        public int Length;
        public IntPtr Value;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_EXTERNAL_TICKET
    {
        public IntPtr ServiceName;
        public IntPtr TargetName;
        public IntPtr ClientName;
        public UNICODE_STRING DomainName;
        public UNICODE_STRING TargetDomainName;
        public UNICODE_STRING AltTargetDomainName;
        public KERB_CRYPTO_KEY SessionKey;
        public uint TicketFlags;
        public uint Flags;
        public long KeyExpirationTime;
        public long StartTime;
        public long EndTime;
        public long RenewUntil;
        public long TimeSkew;
        public int EncodedTicketSize;
        public IntPtr EncodedTicket;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_RETRIEVE_TKT_RESPONSE
    {
        public KERB_EXTERNAL_TICKET Ticket;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_HANDLE
    {
        public IntPtr LowPart;
        public IntPtr HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_TICKET_CACHE_INFO_EX
    {
        public UNICODE_STRING ClientName;
        public UNICODE_STRING ClientRealm;
        public UNICODE_STRING ServerName;
        public UNICODE_STRING ServerRealm;
        public long StartTime;
        public long EndTime;
        public long RenewTime;
        public uint EncryptionType;
        public uint TicketFlags;
    }

    // Ticket flags enumeration
    [Flags]
    public enum TicketFlags : uint
    {
        name_canonicalize = 0x10000,
        forwardable = 0x40000000,
        forwarded = 0x20000000,
        hw_authent = 0x00100000,
        initial = 0x00400000,
        invalid = 0x01000000,
        may_postdate = 0x04000000,
        ok_as_delegate = 0x00040000,
        postdated = 0x02000000,
        pre_authent = 0x00200000,
        proxiable = 0x10000000,
        proxy = 0x08000000,
        renewable = 0x00800000,
        reserved = 0x80000000,
        reserved1 = 0x00000001
    }

    // Encryption types enumeration
    [Flags]
    public enum EncTypes : uint
    {
        DES_CBC_CRC = 0x0001,
        DES_CBC_MD4 = 0x0002,
        DES_CBC_MD5 = 0x0003,
        DES_CBC_raw = 0x0004,
        DES3_CBC_raw = 0x0006,
        DES3_CBC_SHA_1 = 0x0010,
        AES128_CTS_HMAC_SHA1_96 = 0x0011,
        AES256_CTS_HMAC_SHA1_96 = 0x0012,
        AES128_cts_hmac_sha256_128 = 0x0013,
        AES256_cts_hmac_sha384_192 = 0x0014,
        RC4_HMAC_MD5 = 0x0017,
        RC4_HMAC_MD5_EXP = 0x0018
    }

    /// <summary>
    /// Safe string conversion from Unicode pointer
    /// </summary>
    public static string? PtrToStringUniSafe(IntPtr ptr, int length)
    {
        if (ptr == IntPtr.Zero || length <= 0)
            return null;
        
        try
        {
            return Marshal.PtrToStringUni(ptr, length / 2);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Get system error message for Win32 error code
    /// </summary>
    public static string GetLastErrorMessage()
    {
        int error = Marshal.GetLastWin32Error();
        return $"Error {error}: {new System.ComponentModel.Win32Exception(error).Message}";
    }
}


