// SPDX-License-Identifier: Unlicense

using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using static CryptoLab.IHash;

namespace CryptoLab.Hash;

public class BouncyCastleHash : IHash
{
    public string ComputeHash(byte[] data, Algorithm algorithm)
    {

        IDigest digest = algorithm switch
        {
            Algorithm.SHA256 => new Sha256Digest(),
            Algorithm.SHA512 => new Sha512Digest(),
            _ => throw new NotImplementedException(),
        };

        digest.BlockUpdate(data, 0, data.Length);

        byte[] hashedBytes = new byte[digest.GetDigestSize()];

        digest.DoFinal(hashedBytes, 0);

        return Convert.ToHexString(hashedBytes);
    }

    public string ComputeHash(string data, Algorithm algorithm)
    {
        return ComputeHash(Encoding.UTF8.GetBytes(data), algorithm);
    }
}
