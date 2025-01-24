using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoLab
{
    public interface ISymmetric
    {
        byte[] CreateRandomByteArray(int size);

        /// <summary>
        /// Derive a key from a password using a secure key derivation function
        /// </summary>
        /// <param name="password">String used as base</param>
        /// <param name="salt">Random salt</param>
        /// <param name="iterations">Number of iterations</param>
        /// <param name="keySize">In bits</param>
        /// <returns></returns>
        byte[] DeriveKey(string password, byte[] salt, int iterations, int keySize);

        byte[] Encrypt(byte[] key, byte[] iv, byte[] plainData, byte[]? salt = null);

        byte[] Decrypt(byte[] key, byte[] iv, byte[] cipherData);
    }
}
