// SPDX-License-Identifier: Unlicense

namespace CryptoLab
{
    /// <summary>
    /// Interface for symmetric encryption
    /// </summary>
    public interface IAESCipher
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="size"></param>
        /// <returns></returns>
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

        /// <summary>
        /// 
        /// </summary>
        /// <param name="key"></param>
        /// <param name="iv"></param>
        /// <param name="plainData"></param>
        /// <returns></returns>
        byte[] Encrypt(byte[] key, byte[] iv, byte[] plainData);

        /// <summary>
        /// 
        /// </summary>
        /// <param name="key"></param>
        /// <param name="iv"></param>
        /// <param name="cipherData"></param>
        /// <returns></returns>
        byte[] Decrypt(byte[] key, byte[] iv, byte[] cipherData);
    }
}
