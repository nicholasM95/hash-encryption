package io.ordinajworks.security.hashing;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class MD5HashWithSaltServiceTest {
    private MD5HashWithSaltService hashService = new MD5HashWithSaltService();

    @Test
    public void hashPassword() throws NoSuchAlgorithmException {
        String passwordHash = hashService.hashPassword("bad-password");
        System.out.println("PASSWORD_HASH: " + passwordHash);
    }

    @Test
    public void hashPasswordWithSalt() throws NoSuchAlgorithmException {
        String passwordHash = hashService.hashPassword("random-salt", "bad-password");
        Assertions.assertEquals("9bb4ab7502d9150f39db54a8523ff244", passwordHash);
    }

    @Test
    public void validateCorrectPassword() throws NoSuchAlgorithmException {
        boolean passwordCheckOk = hashService.validatePassword("5b1dd297-28d0-42d2-bbe8-e2697f09d2d3", "bad-password", "4b5a639c48f596d6b060a899a53d1ffc");
        Assertions.assertTrue(passwordCheckOk);
    }

    @Test
    public void validateWrongPassword() throws NoSuchAlgorithmException {
        boolean passwordCheckOk = hashService.validatePassword("SALT", "bad-password", "PASSWORD_HASH");
        Assertions.assertFalse(passwordCheckOk);
    }

    @Test
    public void bruteForcePassword() throws IOException, NoSuchAlgorithmException {
        List<String> words = getWords();
        Map<String, String[]> leakedDatabase = getLeakedDatabase();

        leakedDatabase.forEach((user, saltAndHashPassword) -> {
            String salt = saltAndHashPassword[0];
            String passwordHash = saltAndHashPassword[1];

        });
    }

    private List<String> getWords() throws IOException {
        File file = new File(getClass().getClassLoader().getResource("wordlist.txt").getFile());
        List<String> lines = Files.readAllLines(file.toPath(), StandardCharsets.UTF_8);
        return lines;
    }

    private Map<String, String[]> getLeakedDatabase() throws NoSuchAlgorithmException {
        Map<String, String[]> database = new HashMap<>();
        database.put("admin", "3b333714-e44b-40f3-a1ca-cce4885f312a:027a1ac296a6b1abf4154849f083b8d7".split(":"));
        database.put("jos", "3bd3687f-91db-4639-8947-bcedb639d205:8c5bc07fb1d2d82ad0b0ce276d4dea68".split(":"));
        database.put("peter", "32f1ecff-fb61-428f-a11c-44b86c81ebb8:c1c57b07e0de492c79e8681b851cadf2".split(":"));
        database.put("daan", "c946f48e-2ffa-4d6c-9b65-167a27eee310:3d49abb7ea84bc992b6cb226a286a4ca".split(":"));
        database.put("bart", "d13cef3a-0472-42ad-a077-7e867b1db705:d34f36ba63e5aea5d6a0c50bc631d63c".split(":"));
        database.put("dirk", "d13cef3a-0472-42ad-a077-7e867b1db705:d34f36ba63e5aea5d6a0c50bc631d63c".split(":"));
        return database;
    }
}
