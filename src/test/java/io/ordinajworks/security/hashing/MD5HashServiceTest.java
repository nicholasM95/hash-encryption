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

public class MD5HashServiceTest {

    private static final String PASSWORD_HASH_1 = "6fe5394fe01223dae829c964a10ed0ce";

    private MD5HashService hashService = new MD5HashService();

    @Test
    public void hashPassword() throws NoSuchAlgorithmException {
        String passwordHash = hashService.hashPassword("bad-password");
        Assertions.assertEquals(PASSWORD_HASH_1, passwordHash);
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

    @Test
    public void bruteForcePassword() throws IOException, NoSuchAlgorithmException {
        Map<String, String> rainbowTable = getRainbowtable();
        Map<String, String> leakedDatabase = getLeakedDatabase();

        leakedDatabase.forEach((user, passwordHash) -> {
            if (rainbowTable.containsKey(passwordHash)) {
                String password = rainbowTable.get(passwordHash);
                System.out.println(String.format("Found password for %s, password is %s", user, password));
            }
        });
    }


    private Map<String, String> getRainbowtable() throws IOException {
        File file = new File(getClass().getClassLoader().getResource("rainbow-table.txt").getFile());
        List<String> lines = Files.readAllLines(file.toPath(), StandardCharsets.UTF_8);
        Map<String, String> rainbowTable = new HashMap<>();
        lines.forEach(line -> {
            String[] rainbowKeyValue = line.split(":");
            rainbowTable.put(rainbowKeyValue[1], rainbowKeyValue[0]);
        });
        return rainbowTable;
    }

    private Map<String, String> getLeakedDatabase() throws NoSuchAlgorithmException {
        Map<String, String> database = new HashMap<>();
        database.put("admin", "18d6769919266cd0bd6cd78aa405d5d0");
        database.put("jos", "3f9cd3c7b11eb1bae99dddb3d05da3c5");
        database.put("peter", "6a7c1b1d588cd51d12ad44324d614fed");
        database.put("daan", "377edee441ba40cce89db069ac2adeba");
        database.put("bart", "7a069c23854db69bf9cec1b28150f6cb");
        database.put("dirk", "e2704f30f596dbe4e22d1d443b10e004");
        return database;
    }

}
