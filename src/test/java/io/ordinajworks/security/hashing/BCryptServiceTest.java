package io.ordinajworks.security.hashing;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;

public class BCryptServiceTest {
    private BCryptService hashService = new BCryptService();

    private static final String PASSWORD_HASH_1 = "$2a$12$oCfaMexRPPhCE8ev0gO3u.MY9Pq8RmX1T/z0JlaocvmawLIsxwGSG";


    @Test
    public void hashPassword() throws NoSuchAlgorithmException {
        String passwordHash = hashService.hashPassword("bad-password");
        System.out.println(passwordHash);
    }

    @Test
    public void validateCorrectPassword() throws NoSuchAlgorithmException {
        boolean passwordCheckOk = hashService.validatePassword("bad-password", PASSWORD_HASH_1);
        Assertions.assertTrue(passwordCheckOk);
    }

    @Test
    public void validateWrongPassword() throws NoSuchAlgorithmException {
        boolean passwordCheckOk = hashService.validatePassword("wrong-password", PASSWORD_HASH_1);
        Assertions.assertFalse(passwordCheckOk);
    }

}
