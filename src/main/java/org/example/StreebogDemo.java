package org.example;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

public class StreebogDemo {

    public static void main(String[] args) throws Exception {
        // Подключаем провайдера BouncyCastle (даёт ГОСТ-алгоритмы, включая Стрибог)
        Security.addProvider(new BouncyCastleProvider());

        String message = "The quick brown fox jumps over the lazy dog";

        byte[] hash256 = digest("GOST3411-2012-256", message);
        byte[] hash512 = digest("GOST3411-2012-512", message);

        System.out.println("Исходное сообщение: " + message);
        System.out.println("Стрибог-256: " + toHex(hash256));
        System.out.println("Стрибог-512: " + toHex(hash512));
    }

    private static byte[] digest(String algorithm, String message)
            throws NoSuchAlgorithmException, NoSuchProviderException {

        // Берём реализацию хеш-функции Стрибог у провайдера "BC"
        MessageDigest md = MessageDigest.getInstance(algorithm, "BC");
        return md.digest(message.getBytes(StandardCharsets.UTF_8));
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }
}

