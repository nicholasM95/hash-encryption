package io.ordinajworks.security.hashing;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;

public class MD5HashWithSaltPepperServiceTest {
    private MD5HashWithSaltPepperService hashService = new MD5HashWithSaltPepperService();

    @Test
    public void hashPassword() throws NoSuchAlgorithmException {
        String passwordHash = hashService.hashPassword("bad-password");
        System.out.println("PASSWORD_HASH: " + passwordHash);
    }

    @Test
    public void hashPasswordWithSalt() throws NoSuchAlgorithmException {
        String passwordHash = hashService.hashPassword("random-salt", "random-pepper", "bad-password");
        Assertions.assertEquals("4dbc8850e9672510e0170437a7ba9054", passwordHash);
    }

    @Test
    public void validateCorrectPassword() throws NoSuchAlgorithmException {
        boolean passwordCheckOk = hashService.validatePassword("fee50696-43ae-4177-899c-e0f7a663b67a", "d452bbb0-cb1b-48b1-87d1-51a6e3e87849", "bad-password", "95d6e08d76a7dec83fcea46ce7f6a46c");
        Assertions.assertTrue(passwordCheckOk);
    }

    @Test
    public void validateWrongPassword() throws NoSuchAlgorithmException {
        boolean passwordCheckOk = hashService.validatePassword("SALT", "PEPPER", "bad-password", "PASSWORD_HASH");
        Assertions.assertFalse(passwordCheckOk);
    }

}
