package io.ordinajworks.security.encryption.symmetric;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class SymmetricEncryptionServiceTest {

    private static final String ENCODED_MESSAGE = "4v7KXwTEGqXaR+CC3zhb+Q==";

    private SymmetricEncryptionService service;
    private SecretKey secretKey;

    @BeforeEach
    public void init() {
        service = new SymmetricEncryptionService();
        String key = "0/zKy9/6eneup+IhqJvHC9jWEU0ULd3nGTy3VhnU6lg=";
        secretKey = new SecretKeySpec(Base64.getDecoder().decode(key), "AES");
    }

    @Test
    public void encryptMessage() throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        String originalMessage = "Hello world";
        String encodedMessage = service.encryptMessage(originalMessage, secretKey);
        Assertions.assertEquals(ENCODED_MESSAGE, encodedMessage);
    }

    @Test
    public void decryptMessage() throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        String message = service.decryptMessage(ENCODED_MESSAGE, secretKey);
        Assertions.assertEquals("Hello world", message);
    }

}
