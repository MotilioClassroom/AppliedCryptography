using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;


namespace CryptoLab.Symmetric;

/// <summary>
/// ISymmetric implementation using AES from System.Security.Cryptography
/// </summary>
public class SystemAES : ISymmetric
{
    public byte[] CreateRandomByteArray(int size)
    {
        return RandomNumberGenerator.GetBytes(size);
    }

    public byte[] DeriveKey(string password, byte[] salt, int iterations, int keySize)
    {
        var key = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, keySize/8);
        return key;
    }

    public byte[] Encrypt(byte[] key, byte[] iv, byte[] plainData)
    {
        using Aes aes = Aes.Create();

        aes.Key = key;
        aes.IV = iv;

        ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

        using var outputCipherStream = new MemoryStream();

        using var cryptoStream = new CryptoStream(outputCipherStream, encryptor, CryptoStreamMode.Write);

        cryptoStream.Write(plainData, 0, plainData.Length);
        cryptoStream.Clear();

        return outputCipherStream.ToArray();
    }

    public byte[] Decrypt(byte[] key, byte[] iv, byte[] cipherData)
    {
        using Aes aes = Aes.Create();

        aes.Key = key;
        aes.IV = iv;

        ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

        using var inputCipherStream = new MemoryStream(cipherData);
        using var outputPlainStream = new MemoryStream();

        using var cryptoStream = new CryptoStream(inputCipherStream, decryptor, CryptoStreamMode.Read);

        cryptoStream.CopyTo(outputPlainStream);
        cryptoStream.Clear();

        return outputPlainStream.ToArray();
    }

}
