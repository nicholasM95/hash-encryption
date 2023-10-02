package io.ordinajworks.security.hashing;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;

public class MD5HashWithSaltService {

    public String hashPassword(String password) throws NoSuchAlgorithmException {
        String salt = getRandomString();
        System.out.println("SALT: " + salt);
        return hashPassword(salt, password);
    }

    public String hashPassword(String salt, String password) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update((salt + password).getBytes(StandardCharsets.UTF_8));
        byte[] hashAsBytes = md.digest();
        return bytesToHex(hashAsBytes);
    }

    public boolean validatePassword(String salt, String password, String passwordHash) throws NoSuchAlgorithmException {
        String passwordHashCheck = hashPassword(salt, password);
        return passwordHash.equals(passwordHashCheck);
    }


    private static String bytesToHex(byte[] hash) {
        StringBuilder hexString = new StringBuilder(2 * hash.length);
        for (int i = 0; i < hash.length; i++) {
            String hex = Integer.toHexString(0xff & hash[i]);
            if(hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    private static String getRandomString() {
        return UUID.randomUUID().toString();
    }
}
