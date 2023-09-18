using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace REMCCG.Application.Common.Helpers
{
    public static class QueryStringHelper
    {
        private const string EncryptionKey = "0"; // Replace with your own encryption key

        public static string EncryptQueryStringParameter(string parameterValue, string salt)
        {

            // Generate the salt
            //string salt = QueryStringHelper.SaltGenerator.GenerateSalt();

            byte[] clearBytes = Encoding.UTF8.GetBytes(parameterValue);
            byte[] saltBytes = Encoding.UTF8.GetBytes(salt);

            using (Aes encryptor = Aes.Create())
            {
                Rfc2898DeriveBytes pdb = new(EncryptionKey, saltBytes, 10000, HashAlgorithmName.SHA256);

                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);

                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(clearBytes, 0, clearBytes.Length);
                        cs.Close();
                    }
                    parameterValue = Convert.ToBase64String(ms.ToArray());
                }
            }

            return parameterValue;
        }


        public static string DecryptQueryStringParameter(string encryptedParameter, string salt)
        {
            if (string.IsNullOrEmpty(encryptedParameter))
            {
                throw new ArgumentNullException(nameof(encryptedParameter), "The encrypted parameter cannot be null or empty.");
            }

            // Generate the salt
            //string salt = QueryStringHelper.SaltGenerator.GenerateSalt();

            byte[] cipherBytes = Convert.FromBase64String(encryptedParameter);
            byte[] saltBytes = Encoding.UTF8.GetBytes(salt);

            using (Aes encryptor = Aes.Create())
            {
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(EncryptionKey, saltBytes, 10000, HashAlgorithmName.SHA256);

                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);

                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(new MemoryStream(cipherBytes), encryptor.CreateDecryptor(), CryptoStreamMode.Read))
                    {
                        byte[] buffer = new byte[1024];
                        int bytesRead;
                        while ((bytesRead = cs.Read(buffer, 0, buffer.Length)) > 0)
                        {
                            ms.Write(buffer, 0, bytesRead);
                        }
                    }
                    encryptedParameter = Encoding.UTF8.GetString(ms.ToArray());
                }
            }

            return encryptedParameter;
        }

        public static class SaltGenerator
        {
            public static string GenerateSalt()
            {
                const int saltLength = 16; // Adjust the length of the salt as needed

                byte[] saltBytes = new byte[saltLength];

                using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(saltBytes);
                }

                string salt = Convert.ToBase64String(saltBytes);
                return salt;
            }
        }
    }
}
