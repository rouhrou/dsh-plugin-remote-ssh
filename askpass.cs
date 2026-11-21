// DPAPI helper for the SSH connections bundle.
//
// Two roles:
//   askpass      (no arguments)          reads the base64 DPAPI blob named by
//                                        DSH_SSH_SECRET_FILE and prints the
//                                        decrypted password bytes on stdout.
//                                        OpenSSH invokes this through SSH_ASKPASS.
//   --protect    (stdin: base64 UTF-8)   prints the base64 DPAPI blob.
//   --unprotect  (stdin: base64 blob)    prints the base64 UTF-8 plaintext.
//
// All stdin/stdout payloads are ASCII base64 so console code pages cannot
// mangle them. Encryption is current-user DPAPI: only this Windows account can
// decrypt the blob.

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

internal static class SshAskPass
{
    private static byte[] ReadStandardInput()
    {
        using (Stream stdin = Console.OpenStandardInput())
        using (var buffer = new MemoryStream())
        {
            stdin.CopyTo(buffer);
            return buffer.ToArray();
        }
    }

    private static void WriteStandardOutput(byte[] data)
    {
        using (Stream stdout = Console.OpenStandardOutput())
        {
            stdout.Write(data, 0, data.Length);
            stdout.Flush();
        }
    }

    private static string ReadBase64Argument()
    {
        return Encoding.ASCII.GetString(ReadStandardInput()).Trim();
    }

    private static int Protect()
    {
        byte[] plain = Convert.FromBase64String(ReadBase64Argument());
        byte[] encrypted = ProtectedData.Protect(plain, null, DataProtectionScope.CurrentUser);
        WriteStandardOutput(Encoding.ASCII.GetBytes(Convert.ToBase64String(encrypted)));
        return 0;
    }

    private static int Unprotect()
    {
        byte[] encrypted = Convert.FromBase64String(ReadBase64Argument());
        byte[] plain = ProtectedData.Unprotect(encrypted, null, DataProtectionScope.CurrentUser);
        WriteStandardOutput(Encoding.ASCII.GetBytes(Convert.ToBase64String(plain)));
        return 0;
    }

    private static int AskPass()
    {
        string secretFile = Environment.GetEnvironmentVariable("DSH_SSH_SECRET_FILE");
        if (string.IsNullOrEmpty(secretFile) || !File.Exists(secretFile)) return 2;
        byte[] encrypted = Convert.FromBase64String(File.ReadAllText(secretFile, Encoding.ASCII).Trim());
        byte[] plain = ProtectedData.Unprotect(encrypted, null, DataProtectionScope.CurrentUser);
        WriteStandardOutput(plain);
        return 0;
    }

    private static int Main(string[] args)
    {
        try
        {
            if (args.Length == 1 && args[0] == "--protect") return Protect();
            if (args.Length == 1 && args[0] == "--unprotect") return Unprotect();
            return AskPass();
        }
        catch
        {
            return 1;
        }
    }
}
