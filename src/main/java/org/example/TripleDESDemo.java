package org.example;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import java.util.Base64;

public class TripleDESDemo {

    // Алгоритм и режим: 3DES в режиме CBC с добивкой PKCS5
    private static final String TRANSFORMATION = "DESede/CBC/PKCS5Padding";
    private static final String ALGORITHM = "DESede";

    public static void main(String[] args) throws Exception {
        String plaintext = "Привет, 3DES в Java!";

        // 1. Генерируем случайный ключ 3DES (168 бит)
        KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
        keyGen.init(168); // 3 × 56 бит
        SecretKey key = keyGen.generateKey();

        // 2. Генерируем случайный IV (для DES/3DES размер блока 8 байт)
        byte[] ivBytes = new byte[8];
        new SecureRandom().nextBytes(ivBytes);
        IvParameterSpec iv = new IvParameterSpec(ivBytes);

        // 3. Шифрование
        String cipherTextBase64 = encrypt(plaintext, key, iv);

        // 4.1 Генерируем ещё один случайный IV
        byte[] ivBytes2 = new byte[8];
        new SecureRandom().nextBytes(ivBytes2);
        IvParameterSpec iv2 = new IvParameterSpec(ivBytes2);

        // 4.2 Расшифрование
        String decrypted = decrypt(cipherTextBase64, key, iv2);

        // 5. Печатаем, чтобы увидеть, что всё работает
        System.out.println("Открытый текст        : " + plaintext);
        System.out.println("Ключ 3DES (Base64)    : " +
                Base64.getEncoder().encodeToString(key.getEncoded()));
        System.out.println("IV (Base64)           : " +
                Base64.getEncoder().encodeToString(ivBytes));
        System.out.println("IV2 (Base64)           : " +
                Base64.getEncoder().encodeToString(ivBytes2));
        System.out.println("Шифртекст (Base64)    : " + cipherTextBase64);
        System.out.println("Расшифрованный текст  : " + decrypted);
    }

    // Функция шифрования
    public static String encrypt(String plaintext, SecretKey key, IvParameterSpec iv)
            throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] encrypted = cipher.doFinal(plaintext.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    // Функция расшифрования
    public static String decrypt(String cipherTextBase64, SecretKey key, IvParameterSpec iv)
            throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] cipherBytes = Base64.getDecoder().decode(cipherTextBase64);
        byte[] decrypted = cipher.doFinal(cipherBytes);
        return new String(decrypted, "UTF-8");
    }
}
