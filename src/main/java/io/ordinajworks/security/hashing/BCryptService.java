package io.ordinajworks.security.hashing;

import org.springframework.security.crypto.bcrypt.BCrypt;

import java.security.NoSuchAlgorithmException;

public class BCryptService {

    public String hashPassword(String password) throws NoSuchAlgorithmException {
        return BCrypt.hashpw(password, BCrypt.gensalt(12));
    }
    public boolean validatePassword(String password, String passwordHash) throws NoSuchAlgorithmException {
        return BCrypt.checkpw(password, passwordHash);
    }

}
