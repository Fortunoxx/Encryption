// See https://aka.ms/new-console-template for more information
using System.Buffers.Text;
using System.Text;
using System.Text.Json;
using Security;

var stopwatch = new System.Diagnostics.Stopwatch();

Console.WriteLine("=== Initializing Security Examples ===");
Console.WriteLine();

Console.WriteLine("SecurityRSA");
stopwatch.Start();
ExampleRSA();
stopwatch.Stop();
Console.WriteLine($"Elapsed Time: {stopwatch.ElapsedMilliseconds} ms");
Console.WriteLine();

Console.WriteLine("SecurityHybridRsaAes");
stopwatch.Start();
ExampleHybridRsaAes();
stopwatch.Stop();
Console.WriteLine($"Elapsed Time: {stopwatch.ElapsedMilliseconds} ms");
Console.WriteLine();

Console.WriteLine("SecurityHybridX25519AesCgm");
stopwatch.Start();
ExampleHybridX25519AesGcm();
stopwatch.Stop();
Console.WriteLine($"Elapsed Time: {stopwatch.ElapsedMilliseconds} ms");
Console.WriteLine();

// wait for input before exiting
Console.Write("Press any key to exit");
_ = Console.ReadLine();

static void ExampleRSA()
{
    // 1️⃣ Create a new instance of SecurityRSA
     var security = new SecurityRSA(bits: 2048);

    Console.WriteLine($"Public Key: {security.PublicKey}");
    Console.WriteLine($"Private Key: {security.PrivateKey}");

    // 2️⃣ Create a message to encrypt
    var id = Guid.NewGuid();
    var obj = new { payload = new { consentid = id, }, alg = "RSA", iss = "hcv", iat = DateTime.UtcNow, };
    var message = JsonSerializer.Serialize(obj);
    Console.WriteLine($"Original Message: {message}");

    // 3️⃣ Encrypt a message using the Public Key
    var encryptedData = SecurityRSA.EncryptData(message, Convert.FromBase64String(security.PublicKey));
    var encryptedBase64 = Base64Url.EncodeToString(encryptedData);
    Console.WriteLine($"Encrypted Message (Base64): {encryptedBase64} ({encryptedBase64.Length} bytes)");

    // 4️⃣ Decrypt the message using the Private Key
    var decryptedData = SecurityRSA.DecryptData(encryptedData, Convert.FromBase64String(security.PrivateKey));
    var decryptedMessage = Encoding.UTF8.GetString(decryptedData);
    Console.WriteLine($"Decrypted Message: {decryptedMessage}");
}

static void ExampleHybridRsaAes()
{
    // 1️⃣ Create a new instance of SecurityHybrid
    var security = new SecurityHybridRsaAes(bits: 2048);

    Console.WriteLine($"Public Key: {security.PublicKey}");
    Console.WriteLine($"Private Key: {security.PrivateKey}");

    // 2️⃣ Create a message to encrypt
    var id = Guid.NewGuid();
    var obj = new { payload = new { consentid = id, }, alg = "RSA-AES", iss = "hcv", iat = DateTime.UtcNow, };
    var message = JsonSerializer.Serialize(obj);
    Console.WriteLine($"Original Message: {message}");

    // 3️⃣ Encrypt a message using HybridEncryption
    (byte[] encryptedAESKey, byte[] encryptedMessage, byte[] iv) = SecurityHybridRsaAes.EncryptHybrid(message, Convert.FromBase64String(security.PublicKey));
    var encryptedBase64 = Base64Url.EncodeToString(encryptedMessage);
    Console.WriteLine($"Encrypted Message (Base64): {encryptedBase64} ({encryptedBase64.Length} bytes)");

    // 4️⃣ Decrypt the message using HybridDecryption
    string decryptedMessage = SecurityHybridRsaAes.DecryptHybrid(encryptedAESKey, encryptedMessage, iv, Convert.FromBase64String(security.PrivateKey));
    Console.WriteLine($"Decrypted Message: {decryptedMessage}");
}

static void ExampleHybridX25519AesGcm()
{
    // 1️⃣ Generate sender & receiver X25519 key pairs
    var (SenderPrivate, SenderPublic) = SecurityHybridX25519AesCgm.GenerateX25519KeyPair();
    var (ReceiverPrivate, ReceiverPublic) = SecurityHybridX25519AesCgm.GenerateX25519KeyPair();

    // 2️⃣ Compute shared secret using ECDH
    byte[] sharedSecretSender = SecurityHybridX25519AesCgm.ComputeSharedSecret(SenderPrivate, ReceiverPublic);
    byte[] sharedSecretReceiver = SecurityHybridX25519AesCgm.ComputeSharedSecret(ReceiverPrivate, SenderPublic);

    // output keys for debugging
    Console.WriteLine($"Sender Private Key:   {Convert.ToBase64String(SenderPrivate)}");
    Console.WriteLine($"Sender Public Key:    {Convert.ToBase64String(SenderPublic)}");
    Console.WriteLine($"Receiver Private Key: {Convert.ToBase64String(ReceiverPrivate)}");
    Console.WriteLine($"Receiver Public Key:  {Convert.ToBase64String(ReceiverPublic)}");
    // Both shared secrets should be identical
    Console.WriteLine($"Shared Secret Sender: {Convert.ToBase64String(sharedSecretSender)}");
    Console.WriteLine($"Shared Secret Receív: {Convert.ToBase64String(sharedSecretReceiver)}");
    Console.WriteLine($"Shared Secret Match:  {Convert.ToBase64String(sharedSecretSender) == Convert.ToBase64String(sharedSecretReceiver)}");

    // 3️⃣  Create a message to encrypt
    var id = Guid.NewGuid();
    var obj = new { payload = new { consentid = id, }, alg = "X25519-AESCGM", iss = "hcv", iat = DateTime.UtcNow, };
    var message = JsonSerializer.Serialize(obj);
    Console.WriteLine($"Original Message:     {message}");    

    // 4️⃣ Encrypt a message using AES-GCM with the shared secret
    (byte[] ciphertext, byte[] iv, byte[] tag) = SecurityHybridX25519AesCgm.EncryptAESGCM(message, sharedSecretSender);
    var encodedMessage = Base64Url.EncodeToString(ciphertext);
    Console.WriteLine($"Encoded Message:      {encodedMessage}");    
    Console.WriteLine($"Encoded Message Len:  {encodedMessage.Length} bytes");    

    // 5️⃣ Decrypt the message using AES-GCM
    string decryptedMessageReceiver = SecurityHybridX25519AesCgm.DecryptAESGCM(ciphertext, iv, tag, sharedSecretReceiver);
    Console.WriteLine($"Receiver Decrypted:   {decryptedMessageReceiver}");

    string decryptedMessageSender = SecurityHybridX25519AesCgm.DecryptAESGCM(ciphertext, iv, tag, sharedSecretSender);
    Console.WriteLine($"Sender Decrypted:     {decryptedMessageSender}");
}