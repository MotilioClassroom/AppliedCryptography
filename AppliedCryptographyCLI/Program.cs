// SPDX-License-Identifier: Unlicense

namespace AppliedCryptographyCLI;

using CommandDotNet;
using CryptoLab;
using CryptoLab.Asymmetric;
using CryptoLab.Hash;
using CryptoLab.Symmetric;
using System.Security.Cryptography;
using System.Text;

internal class Program
{
    const int KEY_SIZE = 256;
    const int ITERATIONS = 1000;
    const int SALT_SIZE = 16;
    const int IV_SIZE = 16;


    const int RSA_KEY_SIZE = 2048;

    static int Main(string[] args)
    {
        return new AppRunner<Program>().Run(args);
    }


#pragma warning disable CA1822 // Mark members as static
    public void HashTest(string input)
    {
        var HashBC = new BouncyCastleHash();
        var HashSys = new SystemHash();

        var data = Encoding.UTF8.GetBytes(input);

        var hashBC = HashBC.ComputeHash(data, IHash.Algorithm.SHA256);
        var hashSys = HashSys.ComputeHash(input, IHash.Algorithm.SHA256);

        Console.WriteLine($"BouncyCastle : {Convert.ToHexString(hashBC)}");
        Console.WriteLine($"System       : {Convert.ToHexString(hashBC)}");
    }

    public void AESEncrypt(string InputFile, string Password, string OutputFile, [Option('b',null)] bool? UseBouncyCastle, [Option('v', null)] bool? Verbose)
    {
        var input = File.ReadAllBytes(InputFile);

        IAESCipher symmetric = UseBouncyCastle == true ? new BouncyCastleAES() : new SystemAES();

        var salt = symmetric.CreateRandomByteArray(SALT_SIZE);
        var iv = symmetric.CreateRandomByteArray(IV_SIZE);
        var key = symmetric.DeriveKey(Password, salt, ITERATIONS, KEY_SIZE);

        if (Verbose == true)
        {
            Console.WriteLine($"Salt: {ByteArrayToString(salt)}");
            Console.WriteLine($"IV: {ByteArrayToString(iv)}");
            Console.WriteLine($"Key: {ByteArrayToString(key)}");
        }

        var encrypted = symmetric.Encrypt(key, iv, input);

        var final = new byte[IV_SIZE + SALT_SIZE + encrypted.Length];

        iv.CopyTo(final, 0);
        salt.CopyTo(final, IV_SIZE);
        encrypted.CopyTo(final, IV_SIZE + SALT_SIZE);

        File.WriteAllBytes(OutputFile, final);

    }

    public void AESDecrypt(string InputFile, string Password, string OutputFile, [Option('b', null)] bool? UseBouncyCastle, [Option('v',null)] bool? Verbose)
    {
        var input = File.ReadAllBytes(InputFile);

        var iv = input.Take(IV_SIZE).ToArray();
        var salt = input.Skip(IV_SIZE).Take(SALT_SIZE).ToArray();
        var data = input.Skip(IV_SIZE + SALT_SIZE).ToArray();

        IAESCipher symmetric = UseBouncyCastle == true ? new BouncyCastleAES() : new SystemAES();

        var key = symmetric.DeriveKey(Password, salt, ITERATIONS, KEY_SIZE);

        if (Verbose == true)
        {
            Console.WriteLine($"Salt: {ByteArrayToString(salt)}");
            Console.WriteLine($"IV: {ByteArrayToString(iv)}");
            Console.WriteLine($"Key: {ByteArrayToString(key)}");
        }

        var decrypted = symmetric.Decrypt(key,iv,data);

        File.WriteAllBytes(OutputFile, decrypted);

    }

    public void RSAKeyGen(string PrivateKeyFile, string PublicKeyFile, [Option('b', null)] bool? UseBouncyCastle, [Option('v', null)] bool? Verbose)
    {
        IRSACipher rsa = UseBouncyCastle == true ? new BouncyCastleRSA(RSA_KEY_SIZE) : new SystemRSA(RSA_KEY_SIZE);

        var privateKey = rsa.GetPrivateKeyPEM();
        var publicKey = rsa.GetPublicKeyPEM();

        File.WriteAllText(PrivateKeyFile, privateKey);
        File.WriteAllText(PublicKeyFile, publicKey);

        if (Verbose == true)
        {
            Console.WriteLine($"Private Key: {privateKey}");
            Console.WriteLine($"Public Key: {publicKey}");
        }
    }

    public  void RSAEncrypt(string InputFile, string PublicKeyFile, string OutputFile, [Option('b', null)] bool? UseBouncyCastle, [Option('v', null)] bool? Verbose)
    {
        var publicKey = File.ReadAllText(PublicKeyFile);

        IRSACipher rsa = UseBouncyCastle == true ? new BouncyCastleRSA(RSA_KEY_SIZE) : new SystemRSA(RSA_KEY_SIZE);

        rsa.ImportPublicKeyPEM(publicKey);

        var input = File.ReadAllBytes(InputFile);

        var encrypted = rsa.Encrypt(input);

        File.WriteAllBytes(OutputFile, encrypted);

    }

    public void RSADecrypt(string InputFile, string PrivateKeyFile, string OutputFile, [Option('b', null)] bool? UseBouncyCastle, [Option('v', null)] bool? Verbose)
    {
        var privateKey = File.ReadAllText(PrivateKeyFile);

        IRSACipher rsa = UseBouncyCastle == true ? new BouncyCastleRSA(RSA_KEY_SIZE) : new SystemRSA(RSA_KEY_SIZE);

        rsa.ImportPrivateKeyPEM(privateKey);

        var input = File.ReadAllBytes(InputFile);

        var decrypted = rsa.Decrypt(input);

        File.WriteAllBytes(OutputFile, decrypted);
    }

    public void RSASign(string InputFile, string PrivateKeyFile, string OutputFile, [Option('b', null)] bool? UseBouncyCastle, [Option('v', null)] bool? Verbose)
    {
        var privateKey = File.ReadAllText(PrivateKeyFile);

        IRSACipher rsa = UseBouncyCastle == true ? new BouncyCastleRSA(RSA_KEY_SIZE) : new SystemRSA(RSA_KEY_SIZE);

        rsa.ImportPrivateKeyPEM(privateKey);

        var input = File.ReadAllBytes(InputFile);

        var signature = rsa.SignData(input);

        File.WriteAllBytes(OutputFile, signature);
    }

    public void RSAVerify(string InputFile, string PublicKeyFile, string SignatureFile, [Option('b', null)] bool? UseBouncyCastle, [Option('v', null)] bool? Verbose)
    {
        var publicKey = File.ReadAllText(PublicKeyFile);

        IRSACipher rsa = UseBouncyCastle == true ? new BouncyCastleRSA(RSA_KEY_SIZE) : new SystemRSA(RSA_KEY_SIZE);

        rsa.ImportPublicKeyPEM(publicKey);

        var input = File.ReadAllBytes(InputFile);

        var signature = File.ReadAllBytes(SignatureFile);

        var verified = rsa.VerifyData(input, signature);

        Console.WriteLine($"Signature is {(verified ? "valid" : "invalid")}");
    }

#pragma warning restore CA1822 // Mark members as static

    private static string ByteArrayToString(byte[] ba)
    {
        return Convert.ToHexString(ba);
    }


}
