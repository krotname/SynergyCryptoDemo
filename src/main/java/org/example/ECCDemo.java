package org.example;

import javax.crypto.KeyAgreement;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

public class ECCDemo {

    public static void main(String[] args) throws Exception {
        // Сообщение, которое будем подписывать
        String message = "Пример использования ECC в Java";

        // ==== 1. Генерация ECC-ключей для подписи (ECDSA) ====
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        // Одна из стандартных NIST-кривых: secp256r1 (prime256v1)
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
        kpg.initialize(ecSpec);

        KeyPair keyPair = kpg.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        System.out.println("=== ECDSA: Подпись и проверка ===");
        System.out.println("Открытый ключ (Base64):");
        System.out.println(Base64.getEncoder().encodeToString(publicKey.getEncoded()));
        System.out.println();

        // ==== 2. Подпись сообщения ====
        Signature ecdsa = Signature.getInstance("SHA256withECDSA");
        ecdsa.initSign(privateKey);
        ecdsa.update(message.getBytes());
        byte[] signatureBytes = ecdsa.sign();

        String signatureBase64 = Base64.getEncoder().encodeToString(signatureBytes);
        System.out.println("Сообщение: " + message);
        System.out.println("Подпись (Base64): " + signatureBase64);

        // ==== 3. Проверка подписи ====
        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(publicKey);
        verifier.update(message.getBytes());
        boolean valid = verifier.verify(signatureBytes);

        System.out.println("Подпись корректна? " + valid);
        System.out.println();

        // ==== 4. ECDH: обмен ключами и общий секрет ====
        System.out.println("=== ECDH: Обмен ключами и общий секрет ===");

        // Генерация ключей Алисы
        KeyPairGenerator kpgAlice = KeyPairGenerator.getInstance("EC");
        kpgAlice.initialize(ecSpec);
        KeyPair aliceKeyPair = kpgAlice.generateKeyPair();

        // Генерация ключей Боба
        KeyPairGenerator kpgBob = KeyPairGenerator.getInstance("EC");
        kpgBob.initialize(ecSpec);
        KeyPair bobKeyPair = kpgBob.generateKeyPair();

        // Алиса считает общий секрет с использованием своего закрытого и открытого ключа Боба
        byte[] aliceSharedSecret = computeSharedSecret(
                aliceKeyPair.getPrivate(),
                bobKeyPair.getPublic()
        );

        // Боб считает общий секрет с использованием своего закрытого и открытого ключа Алисы
        byte[] bobSharedSecret = computeSharedSecret(
                bobKeyPair.getPrivate(),
                aliceKeyPair.getPublic()
        );

        String aliceSecretB64 = Base64.getEncoder().encodeToString(aliceSharedSecret);
        String bobSecretB64 = Base64.getEncoder().encodeToString(bobSharedSecret);

        System.out.println("Общий секрет Алисы (Base64): " + aliceSecretB64);
        System.out.println("Общий секрет Боба   (Base64): " + bobSecretB64);
        System.out.println("Совпадают ли секреты? " + aliceSecretB64.equals(bobSecretB64));
    }

    /**
     * Вычисляет общий секрет по протоколу ECDH.
     */
    private static byte[] computeSharedSecret(PrivateKey ownPrivateKey, PublicKey otherPublicKey)
            throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(ownPrivateKey);
        ka.doPhase(otherPublicKey, true);
        return ka.generateSecret();
    }
}
