package io.ordinajworks.security.hashing;


import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class MD5HashService {

    public String hashPassword(String password) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(password.getBytes(StandardCharsets.UTF_8));
        byte[] hashAsBytes = md.digest();
        return bytesToHex(hashAsBytes);
    }


    public boolean validatePassword(String password, String passwordHash) throws NoSuchAlgorithmException {
        String passwordHashCheck = hashPassword(password);
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
}
