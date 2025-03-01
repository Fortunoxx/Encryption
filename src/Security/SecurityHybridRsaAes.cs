namespace Security;

using System.Security.Cryptography;
using System.Text;

public class SecurityHybridRsaAes
{
    private readonly byte[] _publicKeyBytes;
    private readonly byte[] _privateKeyBytes;

    public SecurityHybridRsaAes(int bits = 2048)
    {
        using var rsa = RSA.Create(bits); // key size (2048 bits is secure)

        _publicKeyBytes = rsa.ExportRSAPublicKey();
        _privateKeyBytes = rsa.ExportRSAPrivateKey();
    }

    public SecurityHybridRsaAes(byte[] publicKey, byte[] privateKey)
    {
        _publicKeyBytes = publicKey;
        _privateKeyBytes = privateKey;
    }

    public string PublicKey => Convert.ToBase64String(_publicKeyBytes);
    public string PrivateKey => Convert.ToBase64String(_privateKeyBytes);

    // 🔹 Hybrid Encryption: Encrypts message using AES, then encrypts AES Key using RSA
    public static (byte[] encryptedAESKey, byte[] encryptedMessage, byte[] iv) EncryptHybrid(string message, byte[] publicKey)
    {
        using var aes = Aes.Create();
        aes.KeySize = 256; // AES-256 encryption
        aes.GenerateKey();
        aes.GenerateIV();

        // Encrypt the message using AES
        byte[] encryptedMessage = EncryptAES(message, aes.Key, aes.IV);

        // Encrypt the AES Key using RSA
        using RSA rsa = RSA.Create();
        rsa.ImportRSAPublicKey(publicKey, out _);
        var encryptedAESKey = rsa.Encrypt(aes.Key, RSAEncryptionPadding.OaepSHA256);
    
        return (encryptedAESKey, encryptedMessage, aes.IV);
    }

    // 🔹 Hybrid Decryption: Decrypts AES Key using RSA, then decrypts the message using AES
    public static string DecryptHybrid(byte[] encryptedAESKey, byte[] encryptedMessage, byte[] iv, byte[] privateKey)
    {
        using RSA rsa = RSA.Create();
        rsa.ImportRSAPrivateKey(privateKey, out _);
        var aesKey = rsa.Decrypt(encryptedAESKey, RSAEncryptionPadding.OaepSHA256);
    
        return DecryptAES(encryptedMessage, aesKey, iv);
    }

    // 🔐 AES Encryption (Symmetric)
    public static byte[] EncryptAES(string plainText, byte[] key, byte[] iv)
    {
        using Aes aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;
        using ICryptoTransform encryptor = aes.CreateEncryptor();
    
        return encryptor.TransformFinalBlock(Encoding.UTF8.GetBytes(plainText), 0, plainText.Length);
    }

    // 🔑 AES Decryption (Symmetric)
    public static string DecryptAES(byte[] encryptedData, byte[] key, byte[] iv)
    {
        using Aes aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;
        using ICryptoTransform decryptor = aes.CreateDecryptor();
        var decryptedBytes = decryptor.TransformFinalBlock(encryptedData, 0, encryptedData.Length);
    
        return Encoding.UTF8.GetString(decryptedBytes);
    }
}
