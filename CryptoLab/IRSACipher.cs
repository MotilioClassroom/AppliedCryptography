// SPDX-License-Identifier: Unlicense

namespace CryptoLab;

/// <summary>
/// 
/// TODO: Add DER support for exporting and importing keys
/// </summary>
public interface IRSACipher
{

    string GetPrivateKeyPEM();

    void ImportPrivateKeyPEM(string privateKeyPEM);

    string GetPublicKeyPEM();

    void ImportPublicKeyPEM(string publicKeyPEM);

    byte[] Encrypt(byte[] data);

    byte[] Decrypt(byte[] data);
}
