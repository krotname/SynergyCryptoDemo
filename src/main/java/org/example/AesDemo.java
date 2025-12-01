package org.example;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class AesDemo {

    // Алгоритм и режим (современный минимум — CBC + PKCS5Padding; для боевого кода лучше GCM)
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final int AES_KEY_SIZE = 128; // 128 бит достаточно для демонстрации

    public static void main(String[] args) throws Exception {
        String plaintext = "Секретное сообщение про AES";

        // 1. Генерируем случайный ключ AES
        SecretKey key = generateAesKey();

        // 2. Генерируем случайный IV (инициализационный вектор) для CBC
        IvParameterSpec iv = generateIv();

        // 3. Шифруем
        byte[] ciphertext = encrypt(plaintext, key, iv);
        String ciphertextBase64 = Base64.getEncoder().encodeToString(ciphertext);

        // 4. Расшифровываем
        String decrypted = decrypt(ciphertext, key, iv);

        // 5. Печатаем результат
        System.out.println("Открытый текст : " + plaintext);
        System.out.println("Ключ (Base64)  : " + Base64.getEncoder().encodeToString(key.getEncoded()));
        System.out.println("IV   (Base64)  : " + Base64.getEncoder().encodeToString(iv.getIV()));
        System.out.println("Шифртекст      : " + ciphertextBase64);
        System.out.println("Расшифровка    : " + decrypted);
    }

    // Генерация случайного ключа AES
    private static SecretKey generateAesKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(AES_KEY_SIZE); // 128/192/256 — в зависимости от нужд и политики Java
        return keyGen.generateKey();
    }

    // Генерация случайного IV подходящей длины (16 байт для AES)
    private static IvParameterSpec generateIv() {
        byte[] iv = new byte[16]; // блок AES = 16 байт
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    // Шифрование строки в байты с использованием AES/CBC/PKCS5Padding
    private static byte[] encrypt(String plaintext, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        return cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
    }

    // Расшифровка байтов обратно в строку
    private static String decrypt(byte[] ciphertext, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] decryptedBytes = cipher.doFinal(ciphertext);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }
}
