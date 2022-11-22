using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace N_m3u8DL_CLI
{
    public class PolyVideo
    {
        public static void Test()
        {
            Global.SEED_CONST = "68";
            Decrypt(StringToByteArray("b1684a4af659ecdb528fca21953d98a15303d8b725dd559f6d447b4f74e9e0fd"));
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

                byte[] iv = StringToByteArray("01020305070b0d1113171d0705030201");

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

        public static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                .Where(x => x % 2 == 0)
                .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                .ToArray();
        }
    }
}