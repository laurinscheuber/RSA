package Laurin;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;


public class RSA_Laurin {
    private BigInteger p, q, n, phi, e, d;
    private SecureRandom random;
    private int bitLength = 2048;

    public void RSAKeyPairGenerator () {
        random = new SecureRandom();
        p = BigInteger.probablePrime(bitLength / 2, random);
        q = BigInteger.probablePrime(bitLength / 2, random);
        n = p.multiply(q);
        phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        e = BigInteger.probablePrime(bitLength / 2, random);
        while (phi.gcd(e).compareTo(BigInteger.ONE) > 0 && e.compareTo(phi) < 0) {
            e.add(BigInteger.ONE);
        }
        d = e.modInverse(phi);
    }

    public void saveKeyToFile() throws IOException {
        try (PrintWriter publicKeyFile = new PrintWriter(new FileWriter("pk.txt"));
             PrintWriter privateKeyFile = new PrintWriter(new FileWriter("sk.txt"))) {
            publicKeyFile.println("(" + n.toString() + "," + e.toString() + ")");
            privateKeyFile.println("(" + n.toString() + "," + d.toString() + ")");
        }
    }

    public static BigInteger[] encrypt(String text, BigInteger n, BigInteger e) {
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        BigInteger[] encrypted = new BigInteger[bytes.length];

        for (int i = 0; i < bytes.length; i++) {
            encrypted[i] = BigInteger.valueOf(bytes[i]).modPow(e, n);
        }
        return encrypted;
    }

    public static void saveEncryptedToFile(BigInteger[] encrypted) throws IOException {
        try (PrintWriter encryptedFile = new PrintWriter(new FileWriter("chiffre.txt"))) {
            for (BigInteger b : encrypted) {
                encryptedFile.println(b.toString());
            }
        }
    }
}