import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.List;

public class RSA {

    public static void main(String[] args) {
        // Schlüsselpaar generieren
        generateKeyPair();

        // Verschlüsseln
        encryptFile("text.txt", "pk.txt", "chiffre.txt");

        // Entschlüsseln
        decryptFile("chiffre.txt", "sk.txt", "text-d.txt");
    }

    public static void generateKeyPair() {
        SecureRandom random = new SecureRandom();
        BigInteger p = BigInteger.probablePrime(1024, random);
        BigInteger q = BigInteger.probablePrime(1024, random);

        BigInteger n = p.multiply(q);
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        BigInteger e;
        do {
            e = new BigInteger(phi.bitLength(), random);
        } while (e.compareTo(BigInteger.ONE) == 0 || e.compareTo(phi) == 0 || !e.gcd(phi).equals(BigInteger.ONE));

        // create method with euklid algorithm to create d

        //public BigInteger euklidischAlgorith(BigInteger p, BigInteger q) {
        //    BigInteger x = BigInteger.ZERO;
        //    BigInteger y = BigInteger.ONE;
        //    BigInteger lastX = BigInteger.ONE;
        //    BigInteger lastY = BigInteger.ZERO;
        //    BigInteger temp;
        //
        //    while (!b.equals(BigInteger.ZERO)) {
        //        BigInteger[] quotientAndRemainder = a.divideAndRemainder(b);
        //        BigInteger quotient = quotientAndRemainder[0];
        //
        //        a = b;
        //        b = quotientAndRemainder[1];
        //
        //        temp = x;
        //        x = lastX.subtract(quotient.multiply(x));
        //        lastX = temp;
        //
        //        temp = y;
        //        y = lastY.subtract(quotient.multiply(y));
        //        lastY = temp;
        //    }
        //
        //    if (lastY.signum() < 0) {
        //        lastY = lastY.add(a);
        //    }
        //
        //    return lastY;
        //}

//        final BigInteger euklidischAlgorithm(BigInteger p, BigInteger q) {
//            BigInteger x = BigInteger.ZERO;
//            BigInteger y = BigInteger.ONE;
//            BigInteger lastX = BigInteger.ONE;
//            BigInteger lastY = BigInteger.ZERO;
//            BigInteger temp;
//
//            while (!b.equals(BigInteger.ZERO)) {
//                BigInteger[] quotientAndRemainder = a.divideAndRemainder(b);
//                BigInteger quotient = quotientAndRemainder[0];
//            
//                a = b;
//                b = quotientAndRemainder[1];
//            
//                temp = x;
//                x = lastX.subtract(quotient.multiply(x));
//                lastX = temp;
//            
//                temp = y;
//                y = lastY.subtract(quotient.multiply(y));
//                lastY = temp;
//            }
//        
//            if (lastY.signum() < 0) {
//                lastY = lastY.add(phi); // Hier verwenden wir 'phi', anstatt 'a' zu verwenden.
//            }
//        
//            return lastY;
//        }
//
//        BigInteger d = euklidischAlgorithm(e, phi);



        BigInteger d = e.modInverse(phi);

        try {
            Files.write(Paths.get("pk.txt"), (n.toString() + "," + e.toString()).getBytes(StandardCharsets.UTF_8));
            Files.write(Paths.get("sk.txt"), (n.toString() + "," + d.toString()).getBytes(StandardCharsets.UTF_8));
        } catch (IOException ex) {
            System.err.println("Fehler beim Speichern der Schlüssel: " + ex.getMessage());
        }
    }

    public static void encryptFile(String inputFilename, String publicKeyFilename, String outputFilename) {
        try {
            String content = new String(Files.readAllBytes(Paths.get(inputFilename)), StandardCharsets.UTF_8);
            List<String> lines = Files.readAllLines(Paths.get(publicKeyFilename), StandardCharsets.UTF_8);
            String[] parts = lines.get(0).split(",");
            BigInteger n = new BigInteger(parts[0]);
            BigInteger e = new BigInteger(parts[1]);

            StringBuilder cipherText = new StringBuilder();
            for (char ch : content.toCharArray()) {
                BigInteger encryptedChar = BigInteger.valueOf(ch).modPow(e, n);
                cipherText.append(encryptedChar.toString()).append(",");
            }

            Files.write(Paths.get(outputFilename), cipherText.toString().getBytes(StandardCharsets.UTF_8));
        } catch (IOException ex) {
            System.err.println("Fehler beim Verschlüsseln der Datei: " + ex.getMessage());
        }
    }

    public static void decryptFile(String inputFilename, String privateKeyFilename, String outputFilename) {
        try {
            List<String> encryptedLines = Files.readAllLines(Paths.get(inputFilename), StandardCharsets.UTF_8);
            String[] encryptedChars = encryptedLines.get(0).split(",");
            List<String> privateKeyLines = Files.readAllLines(Paths.get(privateKeyFilename), StandardCharsets.UTF_8);

            // zuerst Klammern vom Key entfernen, dann splitten
            String[] parts = privateKeyLines.get(0).substring(1, privateKeyLines.get(0).length() - 1).split(",");
            BigInteger n = new BigInteger(parts[0]);
            BigInteger d = new BigInteger(parts[1]);

            StringBuilder plainText = new StringBuilder();
            for (String encryptedChar : encryptedChars) {
                if (!encryptedChar.isEmpty()) {
                    BigInteger decryptedChar = new BigInteger(encryptedChar).modPow(d, n);
                    plainText.append((char) decryptedChar.intValue());
                }
            }

            Files.write(Paths.get(outputFilename), plainText.toString().getBytes(StandardCharsets.UTF_8));
        } catch (IOException ex) {
            System.err.println("Fehler beim Entschlüsseln der Datei: " + ex.getMessage());
        }
    }

} // End of the RSACipher class
