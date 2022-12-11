using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web;

namespace N_m3u8DL_CLI
{
    public class PolyVideo
    {
        public static void Test()
        {
            Global.SEED_CONST = "68";
            Decrypt(DecodeHexDump("b1684a4af659ecdb528fca21953d98a15303d8b725dd559f6d447b4f74e9e0fd"));
            HexDump(Decrypt(DecodeHexDump("009b24a0c27155c40dc44ec6a1dba791525bb3501f"),
                "E6F0E3504DDB80753F35109F9F77F2A8"));
            Uri uri = new Uri(
                "https://p.bokecc.com/servlet/hlskey?info=E6F0E3504DDB80753F35109F9F77F2A8&t=1670663970&key=97FDF24FB22F1CD392D9ACBF8B2B29C8&fpi=k5KTgMcFmgQFBQeamhhxk--TgMc%3D");

            HttpUtility.ParseQueryString(uri.Query).Get("info");
        }

        public static byte[] Decrypt(byte[] cipher, String keyStr)
        {
            if (keyStr == null)
            {
                return cipher;
            }

            string[] vs = new string[]
            {
                "52096ad53036a538bf40a39e81f3d7fb7ce339829b2fff87348e4344c4dee9cb547b9432a6c2233dee4c950b42fac34e082ea16628d924b2765ba2496d8bd12572f8f66486689816d4a45ccc5d65b6926c704850fdedb9da5e154657a78d9d8490d8ab008cbcd30af7e45805b8b34506d02c1e8fca3f0f02c1afbd0301138a6b3a9111414f67dcea97f2cfcef0b4e67396ac7422e7ad3585e2f937e81c75df6e47f11a711d29c5896fb7620eaa18be1bfc563e4bc6d279209adbc0fe78cd5af41fdda8338807c731b11210592780ec5f60517fa919b54a0d2de57a9f93c99cefa0e03b4dae2af5b0c8ebbb3c83539961172b047eba77d626e169146355210c7d",
                "6355210c7d52096ad53036a538bf40a39e81f3d7fb7ce339829b2fff87348e4344c4dee9cb547b9432a6c2233dee4c950b42fac34e082ea16628d924b2765ba2496d8bd12572f8f66486689816d4a45ccc5d65b6926c704850fdedb9da5e154657a78d9d8490d8ab008cbcd30af7e45805b8b34506d02c1e8fca3f0f02c1afbd0301138a6b3a9111414f67dcea97f2cfcef0b4e67396ac7422e7ad3585e2f937e81c75df6e47f11a711d29c5896fb7620eaa18be1bfc563e4bc6d279209adbc0fe78cd5af41fdda8338807c731b11210592780ec5f60517fa919b54a0d2de57a9f93c99cefa0e03b4dae2af5b0c8ebbb3c83539961172b047eba77d626e16914",
                "7396ac7422e7ad3585e2f937e81c75df6e47f11a711d29c5896fb7620eaa18be1bfc563e4bc6d279209adbc0fe78cd5af41fdda8338807c731b11210592780ec5f60517fa919b54a0d2de57a9f93c99cefa0e03b4dae2af5b0c8ebbb3c83539961172b047eba77d626e169146355210c7d52096ad53036a538bf40a39e81f3d7fb7ce339829b2fff87348e4344c4dee9cb547b9432a6c2233dee4c950b42fac34e082ea16628d924b2765ba2496d8bd12572f8f66486689816d4a45ccc5d65b6926c704850fdedb9da5e154657a78d9d8490d8ab008cbcd30af7e45805b8b34506d02c1e8fca3f0f02c1afbd0301138a6b3a9111414f67dcea97f2cfcef0b4e6",
            };
            var v = DecodeHexDump(vs[cipher[0]]);
            var key = Encoding.UTF8.GetBytes(keyStr);

            var plaintext = Enumerable.Range(0, 16).Select(i =>
            {
                byte b = (byte)(cipher[i + 1] ^ key[i % key.Length]);
                return v[b & 0xff];
            }).ToArray();
            LOGGER.WriteLine(strings.downloadingM3u8Key + " cipher " + BitConverter.ToString(cipher));
            LOGGER.WriteLine(strings.downloadingM3u8Key + " plaintext " + BitConverter.ToString(plaintext));
            return plaintext;
        }

        public static byte[] Decrypt(byte[] cipher)
        {
            var seedConst = Global.SEED_CONST;

            // Creates an instance of the default implementation of the MD5 hash algorithm.
            using (var md5Hash = MD5.Create())
            {
                // Byte array representation of source string
                var sourceBytes = Encoding.UTF8.GetBytes(seedConst);
                // Generate hash value(Byte Array) for input data
                var hashBytes = md5Hash.ComputeHash(sourceBytes);
                // Convert hash byte array to string
                var hash = BitConverter.ToString(hashBytes).Replace("-", string.Empty).ToLower();
                var key = Encoding.UTF8.GetBytes(hash.Substring(0, 16));

                byte[] iv = DecodeHexDump("01020305070b0d1113171d0705030201");

                // Create a new instance of the RijndaelManaged
                // class.  This generates a new key and initialization
                // vector (IV).
                // Encrypt the string to an array of bytes.
                // Decrypt the bytes to a string.
                byte[] plaintext = DecryptStringFromBytes(cipher, key, iv);
                plaintext = plaintext.Take(16).ToArray();
                LOGGER.WriteLine(strings.downloadingM3u8Key + " key " + BitConverter.ToString(key));
                LOGGER.WriteLine(strings.downloadingM3u8Key + " cipher " + BitConverter.ToString(cipher));
                LOGGER.WriteLine(strings.downloadingM3u8Key + " plain " + BitConverter.ToString(plaintext));
                return plaintext;
            }
        }

        static byte[] EncryptStringToBytes(byte[] plainText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;
            // Create an RijndaelManaged object
            // with the specified key and IV.
            using (RijndaelManaged rijAlg = new RijndaelManaged())
            {
                rijAlg.Key = Key;
                rijAlg.IV = IV;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform encryptor = rijAlg.CreateEncryptor(rijAlg.Key, rijAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        //Write all data to the stream.
                        csEncrypt.Write(plainText, 0, plainText.Length);

                        csEncrypt.FlushFinalBlock();
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }


            // Return the encrypted bytes from the memory stream.
            return encrypted;
        }

        static byte[] DecryptStringFromBytes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold
            // the decrypted text.
            byte[] plaintext = new byte[cipherText.Length];

            // Create an RijndaelManaged object
            // with the specified key and IV.
            using (RijndaelManaged rijAlg = new RijndaelManaged())
            {
                rijAlg.Key = Key;
                rijAlg.IV = IV;
                rijAlg.Mode = CipherMode.CBC;
                rijAlg.Padding = PaddingMode.None;

                // Create a decrytor to perform the stream transform.
                ICryptoTransform decryptor = rijAlg.CreateDecryptor(rijAlg.Key, rijAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        // Read the decrypted bytes from the decrypting stream
                        // and place them in a string.
                        var bytesRead = csDecrypt.Read(plaintext, 0, plaintext.Length);

                        plaintext = plaintext.Take(bytesRead).ToArray();
                    }
                }
            }

            return plaintext;
        }

        public static byte[] DecodeHexDump(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                .Where(x => x % 2 == 0)
                .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                .ToArray();
        }

        public static string HexDump(byte[] bytes)
        {
            return BitConverter.ToString(bytes).Replace("-", string.Empty).ToLower();
        }
    }
}