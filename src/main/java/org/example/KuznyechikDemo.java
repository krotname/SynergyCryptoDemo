package org.example;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.Security;

public class KuznyechikDemo {

    public static void main(String[] args) throws Exception {
        // 1. Подключаем провайдера BouncyCastle
        Security.addProvider(new BouncyCastleProvider());

        // 2. Исходный текст
        String plaintext = "Привет, Кузнечик!";
        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);

        // 3. Генерируем случайный ключ 256 бит (32 байта) для Кузнечика
        SecureRandom random = new SecureRandom();
        byte[] keyBytes = new byte[32]; // 256 бит
        random.nextBytes(keyBytes);
        SecretKeySpec key = new SecretKeySpec(keyBytes, "GOST3412-2015");

        // 4. Генерируем случайный IV 128 бит (16 байт) для режима CBC
        byte[] ivBytes = new byte[16]; // размер блока Кузнечика 128 бит
        random.nextBytes(ivBytes);
        IvParameterSpec iv = new IvParameterSpec(ivBytes);

        // 5. Шифрование (Кузнечик в режиме CBC с PKCS7Padding)
        byte[] ciphertext = encrypt(plaintextBytes, key, iv);

        // 6. Расшифрование
        byte[] decrypted = decrypt(ciphertext, key, iv);
        String decryptedText = new String(decrypted, StandardCharsets.UTF_8);

        // 7. Выводим всё на экран
        System.out.println("Plaintext:   " + plaintext);
        System.out.println("Key (hex):   " + toHex(keyBytes));
        System.out.println("IV  (hex):   " + toHex(ivBytes));
        System.out.println("Ciphertext:  " + toHex(ciphertext));
        System.out.println("Decrypted:   " + decryptedText);
    }

    private static byte[] encrypt(byte[] data, SecretKeySpec key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("GOST3412-2015/CBC/PKCS7Padding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        return cipher.doFinal(data);
    }

    private static byte[] decrypt(byte[] data, SecretKeySpec key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("GOST3412-2015/CBC/PKCS7Padding", "BC");
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        return cipher.doFinal(data);
    }

    // Простейшая функция перевода байтов в hex-строку
    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}

