import java.math.BigInteger;
import java.security.SecureRandom;

public class RSA {

    private BigInteger privateKey;
    private BigInteger publicKey;
    private BigInteger modulus;

    // Key generation
    public void generateKeys(int bitLength) {
        SecureRandom random = new SecureRandom();

        // Step 1: Choose two large prime numbers, p and q
        BigInteger p = BigInteger.probablePrime(bitLength, random);
        BigInteger q = BigInteger.probablePrime(bitLength, random);

        // Step 2: Compute n = p * q
        modulus = p.multiply(q);

        // Step 3: Compute the totient (Euler's totient function) phi(n) = (p-1)(q-1)
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));

        // Step 4: Choose a public key e such that 1 < e < phi(n) and gcd(e, phi(n)) = 1
        publicKey = generatePublicExponent(phi);

        // Step 5: Compute the private key d such that (d * e) % phi(n) = 1
        privateKey = publicKey.modInverse(phi);
    }

    // Generate a suitable public exponent e
    private BigInteger generatePublicExponent(BigInteger phi) {
        SecureRandom random = new SecureRandom();
        BigInteger e;

        do {
            // Choose a random value for e such that 1 < e < phi(n)
            e = new BigInteger(phi.bitLength(), random);

            // Ensure that 1 < e < phi(n) and gcd(e, phi(n)) = 1
        } while (e.compareTo(BigInteger.ONE) <= 0 || e.compareTo(phi) >= 0 || !e.gcd(phi).equals(BigInteger.ONE));

        return e;
    }

    // Encryption
    public BigInteger encrypt(String message) {
        byte[] messageBytes = message.getBytes();
        BigInteger plaintext = new BigInteger(messageBytes);

        // ciphertext = plaintext^e mod n
        return plaintext.modPow(publicKey, modulus);
    }

    // Decryption
    public String decrypt(BigInteger ciphertext) {
        // plaintext = ciphertext^d mod n
        BigInteger decryptedMessage = ciphertext.modPow(privateKey, modulus);
        byte[] decryptedBytes = decryptedMessage.toByteArray();

        return new String(decryptedBytes);
    }

    public static void main(String[] args) {
        RSA rsa = new RSA();

        // Key generation with 1024-bit length
        rsa.generateKeys(2048);

        // Original message
        String originalMessage = "If you think cryptography will solve your problem, either you don't understand cryptography, or you don't understand your problem.";

        // Encryption
        BigInteger encryptedMessage = rsa.encrypt(originalMessage);
        System.out.println("\nEncrypted Message: " + encryptedMessage);

        // Decryption
        String decryptedMessage = rsa.decrypt(encryptedMessage);
        System.out.println("\nDecrypted Message: " + decryptedMessage);
    }
}
