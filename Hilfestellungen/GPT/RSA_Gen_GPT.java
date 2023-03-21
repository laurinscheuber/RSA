package Hilfestellungen.GPT;

import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.stream.Collectors;

public class RSA_Gen_GPT {

    private static final SecureRandom random = new SecureRandom();
    private static final String privateKeyFile = "sk.txt";
    private static final String publicKeyFile = "pk.txt";
    private static final String textFile = "text.txt";
    private static final String cipherFile = "chiffre.txt";

    public static void main(String[] args) {
        BigInteger[] keys = generateKeys(2048);
        BigInteger n = keys[0];
        BigInteger e = keys[1];
        BigInteger d = keys[2];

        saveKeyToFile(privateKeyFile, n, d);
        saveKeyToFile(publicKeyFile, n, e);

        String text = readTextFromFile("/Hilfestellung/GPT/",textFile);
        BigInteger[] encryptedText = encryptText(text, n, e);
        writeCipherToFile("Hilfestellung/GPT/" + cipherFile, encryptedText);
    }

    private static BigInteger[] generateKeys(int bitLength) {
        BigInteger p = BigInteger.probablePrime(bitLength / 2, random);
        BigInteger q = BigInteger.probablePrime(bitLength / 2, random);
        BigInteger n = p.multiply(q);
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        BigInteger e = BigInteger.probablePrime(bitLength / 5, random);

        while (!phi.gcd(e).equals(BigInteger.ONE)) {
            e = e.add(BigInteger.ONE);
        }

        BigInteger d = e.modInverse(phi);
        return new BigInteger[] { n, e, d };
    }

    private static void saveKeyToFile(String fileName, BigInteger n, BigInteger k) {
        try (FileWriter writer = new FileWriter(fileName)) {
            writer.write("(" + n.toString() + "," + k.toString() + ")");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static String readTextFromFile(String fileName) {
        try {
            return Files.lines(Paths.get(fileName)).collect(Collectors.joining("\n"));
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    private static BigInteger[] encryptText(String text, BigInteger n, BigInteger e) {
        return text.chars()
                .mapToObj(c -> BigInteger.valueOf(c)
                        .modPow(e, n))
                .toArray(BigInteger[]::new);
    }

    private static void writeCipherToFile(String fileName, BigInteger[] cipherText) {
        try (FileWriter writer = new FileWriter(fileName)) {
            for (int i = 0; i < cipherText.length; i++) {
                writer.write(cipherText[i].toString());
                if (i < cipherText.length - 1) {
                    writer.write(",");
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
