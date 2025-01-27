// SPDX-License-Identifier: Unlicense

using System.Security.Cryptography;

namespace CryptoLab.Asymmetric;

public class SystemRSA : IRSACipher
{
    private readonly RSA rsa;

    public SystemRSA(int keySizeBits = 4096)
    {
        rsa = RSA.Create(keySizeBits);
    }

    public string GetPrivateKeyPEM()
    {
        return rsa.ExportPkcs8PrivateKeyPem();
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
}
