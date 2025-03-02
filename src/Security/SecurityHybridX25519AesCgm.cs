namespace Security;

using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

public class SecurityHybridX25519AesCgm
{
    // X25519 always produces 32-byte shared secrets
    private const int KeySizeInBytes = 32;
    // 16 bytes is the most common and recommended size for AES-GCM tags
    private const int TagSizeInBytes = 16;
    // 96-bit IV (standard for AES-GCM)
    private const int IvSizeInBytes = 12;
    // For the X25519 algorithm, the key size is fixed at 256 bits (32 bytes)
    private const int X25519KeySizeInBits = 256;

    // 🔹 Generate X25519 Key Pair
    public static (byte[] Private, byte[] Public) GenerateX25519KeyPair()
    {
        var keyGen = new X25519KeyPairGenerator();
        keyGen.Init(new KeyGenerationParameters(new SecureRandom(), X25519KeySizeInBits));
        var keyPair = keyGen.GenerateKeyPair();

        var privateKey = ((X25519PrivateKeyParameters)keyPair.Private).GetEncoded();
        var publicKey = ((X25519PublicKeyParameters)keyPair.Public).GetEncoded();
        return (privateKey, publicKey);
    }

    // 🔹 Compute Shared Secret using ECDH
    public static byte[] ComputeSharedSecret(byte[] privateKey, byte[] publicKey)
    {
        if (privateKey == null || privateKey.Length != KeySizeInBytes)
            throw new ArgumentException("Invalid private key length.", nameof(privateKey));
        if (publicKey == null || publicKey.Length != KeySizeInBytes)
            throw new ArgumentException("Invalid public key length.", nameof(publicKey));

        var privateKeyParam = new X25519PrivateKeyParameters(privateKey, 0);
        var publicKeyParam = new X25519PublicKeyParameters(publicKey, 0);

        byte[] sharedSecret = new byte[KeySizeInBytes];
        privateKeyParam.GenerateSecret(publicKeyParam, sharedSecret, 0);
        return sharedSecret;
    }

    // 🔹 Encrypt using AES-256-GCM
    public static (byte[], byte[], byte[]) EncryptAESGCM(string plaintext, byte[] key)
    {
        using var aesGcm = new AesGcm(key, TagSizeInBytes);
        byte[] iv = new byte[IvSizeInBytes];
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
