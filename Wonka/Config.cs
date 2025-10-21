/// <summary>
/// Configuration class for Kerberos Ticket Dumper
/// </summary>
public static class Config
{
    /// <summary>
    /// Target process name for token impersonation
    /// </summary>
    public const string TARGET_PROCESS = "winlogon";
    
    /// <summary>
    /// LSA logon process name
    /// </summary>
    public const string LSA_LOGON_PROCESS = "User32LogonProcess";
    
    /// <summary>
    /// Kerberos authentication package name
    /// </summary>
    public const string KERBEROS_PACKAGE = "kerberos";
    
    /// <summary>
    /// Expected SYSTEM user identity
    /// </summary>
    public const string SYSTEM_IDENTITY = "NT AUTHORITY\\SYSTEM";
    
    /// <summary>
    /// Ticket cache options
    /// </summary>
    public const uint CACHE_OPTIONS = 0x8;
}

/// <summary>
/// Logging helper class
/// </summary>
public static class Logger
{
    public static void Success(string message) => Console.WriteLine($"[+] {message}");
    public static void Error(string message) => Console.WriteLine($"[-] {message}");
    public static void Info(string message) => Console.WriteLine($"[*] {message}");
    public static void Warning(string message) => Console.WriteLine($"[!] {message}");
}