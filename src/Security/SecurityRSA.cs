namespace Security;

using System.Security.Cryptography;
using System.Text;

public class SecurityRSA
{
    private readonly byte[] _publicKeyBytes;
    private readonly byte[] _privateKeyBytes;
    
    public SecurityRSA(int bits = 2048)
    {
        using var rsa = RSA.Create(bits); // key size (2048 bits is secure)

        _publicKeyBytes = rsa.ExportRSAPublicKey();
        _privateKeyBytes = rsa.ExportRSAPrivateKey();
    }

    public SecurityRSA(byte[] publicKey, byte[] privateKey)
    {
        _publicKeyBytes = publicKey;
        _privateKeyBytes = privateKey;
    }

    public string PublicKey => Convert.ToBase64String(_publicKeyBytes);
    public string PrivateKey => Convert.ToBase64String(_privateKeyBytes);

    // 🔒 Encrypt Data with Public Key
    public static byte[] EncryptData(string message, byte[] publicKey)
    {
        using RSA rsa = RSA.Create();
        rsa.ImportRSAPublicKey(publicKey, out _);

        return rsa.Encrypt(Encoding.UTF8.GetBytes(message), RSAEncryptionPadding.OaepSHA256);
    }

    // 🔑 Decrypt Data with Private Key
    public static byte[] DecryptData(byte[] encryptedData, byte[] privateKey)
    {
        using RSA rsa = RSA.Create();
        rsa.ImportRSAPrivateKey(privateKey, out _);

        return rsa.Decrypt(encryptedData, RSAEncryptionPadding.OaepSHA256);
    }
}