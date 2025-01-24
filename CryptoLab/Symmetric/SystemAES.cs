using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;


namespace CryptoLab.Symmetric;

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

    public byte[] Encrypt(byte[] key, byte[] iv, byte[] plainData, byte[]? salt = null)
    {
        using Aes aes = Aes.Create();

        aes.Key = key;
        aes.IV = iv;

        ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

        using MemoryStream outputCipherStream = new();
        outputCipherStream.Write(aes.IV, 0, aes.IV.Length);
        if (salt != null)
        {
            outputCipherStream.Write(salt, 0, salt.Length);
        }

        using CryptoStream cryptoStream = new(outputCipherStream, encryptor, CryptoStreamMode.Write);

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

        using MemoryStream inputCipherStream = new(cipherData);
        using MemoryStream outputPlainStream = new();

        using CryptoStream cryptoStream = new(inputCipherStream, decryptor, CryptoStreamMode.Read);

        cryptoStream.CopyTo(outputPlainStream);
        cryptoStream.Clear();

        return outputPlainStream.ToArray();
    }

}
