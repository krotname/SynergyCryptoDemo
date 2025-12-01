package org.example;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class RsaDemo {

    // Генерация пары ключей RSA
    private static KeyPair generateKeyPair(int keySize) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(keySize); // 2048 бит — минимально адекватно сегодня
        return keyGen.generateKeyPair();
    }

    // Шифрование открытым ключом
    private static String encrypt(String plaintext, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    // Расшифрование закрытым ключом
    private static String decrypt(String ciphertextBase64, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decoded = Base64.getDecoder().decode(ciphertextBase64);
        byte[] decrypted = cipher.doFinal(decoded);
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) throws Exception {
        // 1. Генерируем пару ключей
        KeyPair keyPair = generateKeyPair(2048);
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        String originalText = "Привет, RSA!";

        // 2. Шифруем открытым ключом
        String encrypted = encrypt(originalText, publicKey);

        // 3. Расшифровываем закрытым ключом
        String decrypted = decrypt(encrypted, privateKey);

        // 4. Печатаем результат
        System.out.println("Открытый ключ:  " + Base64.getEncoder().encodeToString(publicKey.getEncoded()));
        System.out.println("Закрытый ключ:  " + Base64.getEncoder().encodeToString(privateKey.getEncoded()));
        System.out.println("Исходный текст: " + originalText);
        System.out.println("Шифртекст:      " + encrypted);
        System.out.println("Расшифровка:    " + decrypted);
    }
}

