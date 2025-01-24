namespace AppliedCryptographyCLI;

using CommandDotNet;
using CryptoLab;
using CryptoLab.Symmetric;
using System.Text;

internal class Program
{
    const int KEY_SIZE = 256;
    const int ITERATIONS = 1000;
    const int SALT_SIZE = 16;
    const int IV_SIZE = 16;

    static int Main(string[] args)
    {
        return new AppRunner<Program>().Run(args);
    }

    public void SymmetricEncrypt(string InputFile, string Password, string OutputFile, [Option('v', null)] bool? verbose)
    {
        var input = File.ReadAllBytes(InputFile);

        ISymmetric symmetric = new SystemAES();

        var salt = symmetric.CreateRandomByteArray(SALT_SIZE);
        var iv = symmetric.CreateRandomByteArray(IV_SIZE);
        var key = symmetric.DeriveKey(Password, salt, ITERATIONS, KEY_SIZE);

        if (verbose == true)
        {
            Console.WriteLine($"Salt: {ByteArrayToString(salt)}");
            Console.WriteLine($"IV: {ByteArrayToString(iv)}");
            Console.WriteLine($"Key: {ByteArrayToString(key)}");
        }

        var encrypted = symmetric.Encrypt(key, iv, input, salt);

        File.WriteAllBytes(OutputFile, encrypted);

    }

    public void SymmetricDecrypt(string InputFile, string Password, string OutputFile, [Option('v',null)] bool? verbose)
    {
        var input = File.ReadAllBytes(InputFile);

        var iv = input.Take(IV_SIZE).ToArray();
        var salt = input.Skip(IV_SIZE).Take(SALT_SIZE).ToArray();
        var data = input.Skip(IV_SIZE + SALT_SIZE).ToArray();

        ISymmetric symmetric = new SystemAES();

        var key = symmetric.DeriveKey(Password, salt, ITERATIONS, KEY_SIZE);

        if (verbose == true)
        {
            Console.WriteLine($"Salt: {ByteArrayToString(salt)}");
            Console.WriteLine($"IV: {ByteArrayToString(iv)}");
            Console.WriteLine($"Key: {ByteArrayToString(key)}");
        }

        var decrypted = symmetric.Decrypt(key,iv,data);

        File.WriteAllBytes(OutputFile, decrypted);

    }

    public void AsymmetricEncrypt(string InputFile, string KeyFile, string OutputFile)
    {

    }

    private static string ByteArrayToString(byte[] ba)
    {
        return BitConverter.ToString(ba).Replace("-", "");
    }


}
