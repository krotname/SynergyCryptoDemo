package org.example;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

public class HashDemo {

    // Утилита: посчитать хэш и вернуть в hex-строке
    private static String digest(String algorithm, String input) {
        try {
            MessageDigest md = MessageDigest.getInstance(algorithm);
            byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Алгоритм не поддерживается: " + algorithm, e);
        }
    }

    public static void main(String[] args) {
        String msg1 = "Hello, world!";
        String msg2 = "Hello, world?"; // одна буква отличается – демонстрация лавинного эффекта

        System.out.println("Оригинальное сообщение      : " + msg1);
        System.out.println("Похожее сообщение (1 символ): " + msg2);
        System.out.println();

        String[] algorithms = {
                "MD5",          // 128 бит – взломан, только для демонстрации
                "SHA-1",        // 160 бит – уязвим, не использовать для новых систем
                "SHA-256",      // SHA-2
                "SHA-512",      // SHA-2
                "SHA3-256",     // SHA-3 (Keccak)
                "SHA3-512"      // SHA-3 (Keccak)
        };

        for (String alg : algorithms) {
            String h1 = digest(alg, msg1);
            String h2 = digest(alg, msg2);

            System.out.println("Алгоритм: " + alg);
            System.out.println("  Хэш(msg1): " + h1);
            System.out.println("  Хэш(msg2): " + h2);
            System.out.println("  Совпадает ли хэш? " + h1.equals(h2));
            System.out.println();
        }
    }
}
