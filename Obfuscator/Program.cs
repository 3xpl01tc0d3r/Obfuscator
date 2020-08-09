using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace Obfuscator
{
    class Program
    {
        //https://github.com/mvelazc0/defcon27_csharp_workshop/blob/master/Labs/lab4/1.cs#L10
        private static byte[] XOR(byte[] cipher, byte[] key)
        {

            byte[] xored = new byte[cipher.Length];

            for (int i = 0; i < cipher.Length; i++)
            {
                xored[i] = (byte)(cipher[i] ^ key[i % key.Length]);
            }

            return xored;
        }

        //https://github.com/mvelazc0/defcon27_csharp_workshop/blob/master/Labs/lab4/3.cs#L64
        public static byte[] AES_Encrypt(byte[] bytesToBeEncrypted, byte[] passwordBytes)
        {
            byte[] encryptedBytes = null;

            byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

            using (MemoryStream ms = new MemoryStream())
            {
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    AES.KeySize = 256;
                    AES.BlockSize = 128;

                    var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);

                    AES.Mode = CipherMode.CBC;

                    using (var cs = new CryptoStream(ms, AES.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
                        cs.Close();
                    }
                    encryptedBytes = ms.ToArray();
                }
            }

            return encryptedBytes;
        }

        public static byte[] AES_Decrypt(byte[] bytesToBeDecrypted, byte[] passwordBytes)
        {
            byte[] decryptedBytes = null;
            byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

            using (MemoryStream ms = new MemoryStream())
            {
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    AES.KeySize = 256;
                    AES.BlockSize = 128;

                    var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);

                    AES.Mode = CipherMode.CBC;

                    using (var cs = new CryptoStream(ms, AES.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length);
                        cs.Close();
                    }
                    decryptedBytes = ms.ToArray();
                }
            }

            return decryptedBytes;
        }


        public static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        public static byte[] convertfromc(string val)
        {
            string rval = val.Replace("\"", string.Empty).Replace("\r\n", string.Empty).Replace("x", string.Empty);
            string[] sval = rval.Split('\\');

            var fval = string.Empty;
            foreach (var lval in sval)
            {
                if (lval != null)
                {
                    fval += lval;
                }
            }

            return StringToByteArray(fval);
        }

        public static string ByteArrayToString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }

        public static byte[] GetRawShellcode(string url)
        {
            WebClient client = new WebClient();
            client.Proxy = WebRequest.GetSystemWebProxy();
            client.Proxy.Credentials = CredentialCache.DefaultCredentials;
            byte[] shellcode = client.DownloadData(url);

            return shellcode;
        }
        public static string GetShellcode(string url)
        {
            WebClient client = new WebClient();
            client.Proxy = WebRequest.GetSystemWebProxy();
            client.Proxy.Credentials = CredentialCache.DefaultCredentials;
            string shellcode = client.DownloadString(url);

            return shellcode;
        }
        public static void PrintError(string error)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(error);
            Console.ResetColor();
        }

        public static void PrintSuccess(string success)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine(success);
            Console.ResetColor();
        }
        public static void PrintInfo(string info)
        {
            Console.ForegroundColor = ConsoleColor.Blue;
            Console.WriteLine(info);
            Console.ResetColor();
        }

        public static void logo()
        {
            Console.WriteLine();
            Console.WriteLine("##########################################################################");
            Console.WriteLine("#   ____  ____  ______ _    _  _____  _____       _______ ____  _____   #");
            Console.WriteLine("#  / __ \\|  _ \\|  ____| |  | |/ ____|/ ____|   /\\|__   __/ __ \\|  __ \\  #");
            Console.WriteLine("# | |  | | |_) | |__  | |  | | (___ | |       /  \\  | | | |  | | |__) | #");
            Console.WriteLine("# | |  | |  _ <|  __| | |  | |\\___ \\| |      / /\\ \\ | | | |  | |  _  /  #");
            Console.WriteLine("# | |__| | |_) | |    | |__| |____) | |____ / ____ \\| | | |__| | | \\ \\  #");
            Console.WriteLine("#  \\____/|____/|_|     \\____/|_____/ \\_____/_/    \\_\\_|  \\____/|_|  \\_\\ #");
            Console.WriteLine("##########################################################################");
            Console.WriteLine();
        }
        public static void help()
        {

            string help = @"
*****************Help*****************
[+] The program is designed to obfuscate the shellcode.
[+] Currently the tool supports 2 encryption.
    1) XOR
    2) AES

[+] The tool accepts shellcode in 4 formats.
    1) base64
    2) hex
    3) c
    4) raw


Usage           Description
-----           -----------
/f              Specify the format of the shellcode
                base64
                hex
                c
                raw
/enc            Specify the encryption type (aes or xor) in which the shellcode will be encrypted
/key            Specify the key that will be used to encrypt the shellcode (default = SuperStrongKey)
/path           Specify the path of the file that contains the shellcode
/url            Specify the url where the shellcode is hosted
/o              Specify the file path to save the encrypted shellcode (default = output.bin)
/help           Show help

";
            Console.WriteLine(help);
        }
        static void Main(string[] args)
        {
            try
            {
                logo();
                // https://github.com/GhostPack/Rubeus/blob/master/Rubeus/Domain/ArgumentParser.cs#L10

                var arguments = new Dictionary<string, string>();
                foreach (var argument in args)
                {
                    var idx = argument.IndexOf(':');
                    if (idx > 0)
                        arguments[argument.Substring(0, idx)] = argument.Substring(idx + 1);
                    else
                        arguments[argument] = string.Empty;
                }

                WindowsIdentity identity = WindowsIdentity.GetCurrent();
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                if (principal.IsInRole(WindowsBuiltInRole.Administrator))
                {
                    Console.WriteLine($"[+] Process running with {principal.Identity.Name} privileges with HIGH integrity.");
                }
                else
                {
                    Console.WriteLine($"[+] Process running with {principal.Identity.Name} privileges with MEDIUM / LOW integrity.");
                }

                if (arguments.Count == 0)
                {
                    PrintError("[-] No arguments specified. Please refer the help section for more details.");
                    help();
                }
                else if (arguments.ContainsKey("/help"))
                {
                    help();
                }
                else if (arguments.Count < 3)
                {
                    PrintError("[-] Some arguments are missing. Please refer the help section for more details.");
                    help();
                }
                else if (arguments.Count >= 3)
                {
                    string key = "SuperStrongKey";
                    string shellcode = null;
                    byte[] rawshellcode = new byte[] { };
                    if (arguments.ContainsKey("/path") && System.IO.File.Exists(arguments["/path"]))
                    {
                        if (arguments["/f"] == "raw")
                        {
                            rawshellcode = System.IO.File.ReadAllBytes(arguments["/path"]);
                        }
                        else
                        {
                            shellcode = System.IO.File.ReadAllText(arguments["/path"]);
                        }

                    }
                    else if (arguments.ContainsKey("/url"))
                    {
                        if (arguments["/f"] == "raw")
                        {
                            rawshellcode = GetRawShellcode(arguments["/url"]);
                        }
                        else
                        {
                            shellcode = GetShellcode(arguments["/url"]);
                        }
                    }

                    if (shellcode != null || rawshellcode.Length > 0)
                    {

                        byte[] buf = new byte[] { };

                        if (arguments.ContainsKey("/key"))
                        {
                            key = (arguments["/key"]);
                        }
                        PrintInfo($"[!] Shellcode will be encrypted using '{key}' key");
                        if (arguments["/enc"] == "xor")
                        {
                            byte[] xorshellcode = new byte[] { };
                            if (arguments["/f"] == "base64")
                            {
                                buf = Convert.FromBase64String(shellcode);
                                xorshellcode = XOR(buf, Encoding.ASCII.GetBytes(key));
                                PrintSuccess("[+] Shellcode encrypted successfully.");
                                //Console.WriteLine(Convert.ToBase64String(xorshellcode));
                                if (arguments.ContainsKey("/o"))
                                {
                                    System.IO.File.WriteAllText(arguments["/o"], Convert.ToBase64String(xorshellcode));
                                    PrintSuccess($"[+] Output saved in '{arguments["/o"]}' file.");
                                }
                                else
                                {
                                    System.IO.File.WriteAllText("output.bin", Convert.ToBase64String(xorshellcode));
                                    PrintSuccess($"[+] Output saved in 'output.bin' file.");
                                }
                            }
                            else if (arguments["/f"] == "hex")
                            {
                                buf = StringToByteArray(shellcode);
                                xorshellcode = XOR(buf, Encoding.ASCII.GetBytes(key));
                                PrintSuccess("[+] Shellcode encrypted successfully.");
                                //Console.WriteLine(ByteArrayToString(xorshellcode));
                                if (arguments.ContainsKey("/o"))
                                {
                                    System.IO.File.WriteAllText(arguments["/o"], ByteArrayToString(xorshellcode));
                                    PrintSuccess($"[+] Output saved in '{arguments["/o"]}' file.");
                                }
                                else
                                {
                                    System.IO.File.WriteAllText("output.bin", ByteArrayToString(xorshellcode));
                                    PrintSuccess($"[+] Output saved in 'output.bin' file.");
                                }
                            }
                            else if (arguments["/f"] == "c")
                            {
                                buf = convertfromc(shellcode);
                                xorshellcode = XOR(buf, Encoding.ASCII.GetBytes(key));
                                StringBuilder newshellcode = new StringBuilder();
                                for (int i = 0; i < xorshellcode.Length; i++)
                                {
                                    newshellcode.Append("\\x");
                                    newshellcode.AppendFormat("{0:x2}", xorshellcode[i]);
                                }
                                PrintSuccess("[+] Shellcode encrypted successfully.");
                                //Console.WriteLine(newshellcode);
                                if (arguments.ContainsKey("/o"))
                                {
                                    System.IO.File.WriteAllText(arguments["/o"], newshellcode.ToString());
                                    PrintSuccess($"[+] Output saved in '{arguments["/o"]}' file.");
                                }
                                else
                                {
                                    System.IO.File.WriteAllText("output.bin", newshellcode.ToString());
                                    PrintSuccess($"[+] Output saved in 'output.bin' file.");
                                }
                            }
                            else if (arguments["/f"] == "raw")
                            {
                                xorshellcode = XOR(rawshellcode, Encoding.ASCII.GetBytes(key));
                                PrintSuccess("[+] Shellcode encrypted successfully.");
                                if (arguments.ContainsKey("/o"))
                                {
                                    System.IO.File.WriteAllBytes(arguments["/o"], xorshellcode);
                                    PrintSuccess($"[+] Output saved in '{arguments["/o"]}' file.");
                                }
                                else
                                {
                                    System.IO.File.WriteAllBytes("output.bin", xorshellcode);
                                    PrintSuccess($"[+] Output saved in 'output.bin' file.");
                                }
                            }
                            else
                            {
                                PrintError("[-] Please specify correct shellcode format.");
                            }
                        }
                        else if (arguments["/enc"] == "aes")
                        {
                            byte[] passwordBytes = Encoding.UTF8.GetBytes(key);
                            passwordBytes = SHA256.Create().ComputeHash(passwordBytes);
                            byte[] bytesEncrypted = new byte[] { };
                            if (arguments["/f"] == "base64")
                            {
                                buf = Convert.FromBase64String(shellcode);
                                bytesEncrypted = AES_Encrypt(buf, passwordBytes);
                                PrintSuccess("[+] Shellcode encrypted successfully.");
                                //Console.WriteLine(Convert.ToBase64String(bytesEncrypted));
                                if (arguments.ContainsKey("/o"))
                                {
                                    System.IO.File.WriteAllText(arguments["/o"], Convert.ToBase64String(bytesEncrypted));
                                    PrintSuccess($"[+] Output saved in '{arguments["/o"]}' file.");
                                }
                                else
                                {
                                    System.IO.File.WriteAllText("output.bin", Convert.ToBase64String(bytesEncrypted));
                                    PrintSuccess($"[+] Output saved in 'output.bin' file.");
                                }
                            }
                            else if (arguments["/f"] == "hex")
                            {
                                buf = StringToByteArray(shellcode);
                                bytesEncrypted = AES_Encrypt(buf, passwordBytes);
                                PrintSuccess("[+] Shellcode encrypted successfully.");
                                //Console.WriteLine(ByteArrayToString(bytesEncrypted));
                                if (arguments.ContainsKey("/o"))
                                {
                                    System.IO.File.WriteAllText(arguments["/o"], ByteArrayToString(bytesEncrypted));
                                    PrintSuccess($"[+] Output saved in '{arguments["/o"]}' file.");
                                }
                                else
                                {
                                    System.IO.File.WriteAllText("output.bin", ByteArrayToString(bytesEncrypted));
                                    PrintSuccess($"[+] Output saved in 'output.bin' file.");
                                }
                            }
                            else if (arguments["/f"] == "c")
                            {
                                buf = convertfromc(shellcode);
                                bytesEncrypted = AES_Encrypt(buf, passwordBytes);
                                StringBuilder newshellcode = new StringBuilder();
                                for (int i = 0; i < bytesEncrypted.Length; i++)
                                {
                                    newshellcode.Append("\\x");
                                    newshellcode.AppendFormat("{0:x2}", bytesEncrypted[i]);
                                }
                                PrintSuccess("[+] Shellcode encrypted successfully.");
                                //Console.WriteLine(newshellcode);
                                if (arguments.ContainsKey("/o"))
                                {
                                    System.IO.File.WriteAllText(arguments["/o"], newshellcode.ToString());
                                    PrintSuccess($"[+] Output saved in '{arguments["/o"]}' file.");
                                }
                                else
                                {
                                    System.IO.File.WriteAllText("output.bin", newshellcode.ToString());
                                    PrintSuccess($"[+] Output saved in 'output.bin' file.");
                                }
                            }
                            else if (arguments["/f"] == "raw")
                            {
                                bytesEncrypted = AES_Encrypt(rawshellcode, passwordBytes);
                                if (arguments.ContainsKey("/o"))
                                {
                                    System.IO.File.WriteAllBytes(arguments["/o"], bytesEncrypted);
                                    PrintSuccess($"[+] Output saved in '{arguments["/o"]}' file.");
                                }
                                else
                                {
                                    System.IO.File.WriteAllBytes("output.bin", bytesEncrypted);
                                    PrintSuccess($"[+] Output saved in 'output.bin' file.");
                                }
                            }
                            else
                            {
                                PrintError("[-] Please specify correct shellcode format.");
                            }
                        }
                        else
                        {
                            PrintError("[-] Please specify correct encryption type.");
                        }
                    }
                    else
                    {
                        PrintError("[-] Please check the specified file path or the URL.");
                    }
                }
                else
                {
                    PrintError("[-] File doesn't exists. Please check the specified file path.");
                }
            }
            catch (Exception ex)
            {
                PrintError(ex.Message);
            }
        }
    }
}
