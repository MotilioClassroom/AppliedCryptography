// SPDX-License-Identifier: Unlicense

using System.Security.Cryptography;

namespace CryptoLab.Asymmetric;

public class SystemRSA(int keySizeBits = 4096) : IRSACipher
{
    private readonly RSA rsa = RSA.Create(keySizeBits);

    public string GetPrivateKeyPEM()
    {
        return rsa.ExportRSAPrivateKeyPem();
    }

    public void ImportPrivateKeyPEM(string privateKeyPEM)
    {
        rsa.ImportFromPem(privateKeyPEM);
    }

    public string GetPublicKeyPEM()
    {
        return rsa.ExportRSAPublicKeyPem();
    }

    public void ImportPublicKeyPEM(string publicKeyPEM)
    {
        rsa.ImportFromPem(publicKeyPEM);
    }

    public byte[] Encrypt(byte[] data)
    {
        var encryptedData = rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);

        return encryptedData;
    }

    public byte[] Decrypt(byte[] data)
    {
        var decryptedData = rsa.Decrypt(data, RSAEncryptionPadding.OaepSHA256);

        return decryptedData;
    }

    public byte[] SignData(byte[] data)
    {
        var signature = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        
        return signature;
    }

    public bool VerifyData(byte[] data, byte[] signature)
    {
        var isVerified = rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return isVerified;
    }
}
