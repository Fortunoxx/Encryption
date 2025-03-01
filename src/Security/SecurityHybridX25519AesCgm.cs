namespace Security;

using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

public class SecurityHybridX25519AesCgm
{
    private const int TagSizeInBytes = 16;

    // 🔹 Generate X25519 Key Pair
    public static (byte[] Private, byte[] Public) GenerateX25519KeyPair()
    {
        var keyGen = new X25519KeyPairGenerator();
        keyGen.Init(new KeyGenerationParameters(new SecureRandom(), 256));
        var keyPair = keyGen.GenerateKeyPair();

        var privateKey = ((X25519PrivateKeyParameters)keyPair.Private).GetEncoded();
        var publicKey = ((X25519PublicKeyParameters)keyPair.Public).GetEncoded();
        return (privateKey, publicKey);
    }

    
    // 🔹 Compute Shared Secret using ECDH
    public static byte[] ComputeSharedSecret(byte[] privateKey, byte[] publicKey)
    {
        var privateKeyParam = new X25519PrivateKeyParameters(privateKey, 0);
        var publicKeyParam = new X25519PublicKeyParameters(publicKey, 0);

        byte[] sharedSecret = new byte[32]; // X25519 always produces 32-byte shared secrets
        privateKeyParam.GenerateSecret(publicKeyParam, sharedSecret, 0);
        return sharedSecret;
    }

    // 🔹 Encrypt using AES-256-GCM
    public static (byte[], byte[], byte[]) EncryptAESGCM(string plaintext, byte[] key)
    {
        using var aesGcm = new AesGcm(key, TagSizeInBytes);
        byte[] iv = new byte[12]; // 96-bit IV (standard for AES-GCM)
        RandomNumberGenerator.Fill(iv);

        byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        byte[] ciphertext = new byte[plaintextBytes.Length];
        byte[] tag = new byte[TagSizeInBytes]; // Authentication tag

        aesGcm.Encrypt(iv, plaintextBytes, ciphertext, tag);
        return (ciphertext, iv, tag);
    }

    // 🔹 Decrypt using AES-256-GCM
    public static string DecryptAESGCM(byte[] ciphertext, byte[] iv, byte[] tag, byte[] key)
    {
        using var aesGcm = new AesGcm(key, TagSizeInBytes);
        byte[] plaintextBytes = new byte[ciphertext.Length];
        aesGcm.Decrypt(iv, ciphertext, tag, plaintextBytes);
        return Encoding.UTF8.GetString(plaintextBytes);
    }
}
