// SPDX-License-Identifier: Unlicense

namespace CryptoLab;

public interface IHash
{
    public enum Algorithm
    {
        MD5,
        SHA256,
        SHA512,
    }

    byte[] ComputeHash(byte[] data, Algorithm algorithm);

    byte[] ComputeHash(string data, Algorithm algorithm);

}
