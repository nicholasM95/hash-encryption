package io.ordinajworks.security.encryption.asymmetric;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class AsymmetricEncryptionServiceTest {
    private AsymmetricEncryptionService service;
    private Map<String, KeyPair> keys;

    @BeforeEach
    public void init() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        service = new AsymmetricEncryptionService();
        keys = getFixedKeys2();
    }

    @Test
    public void sendMessageToDaan() throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {

    }

    private String bytesToString(byte[] value) {
        return new String(value, StandardCharsets.UTF_8);
    }

    private Map<String, KeyPair> getFixedKeys() throws NoSuchAlgorithmException, InvalidKeySpecException {
        Map<String, KeyPair> keys = new HashMap<>();

        KeyFactory kf = KeyFactory.getInstance("RSA"); // or "EC" or whatever

        String publicKeyDaanAsBase64 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDSs/+XzxTenwVQnrctym0NcNP3rlqvYK2PXQF/W4bxJB9OYcOn2rCXW0no0ysTfCjTmuBymx+QGHz32bv6XgGB2JcaTYScDMPPi5oU7UvZXS7jViTlQr24560Joo0NQrZFsQ+k91f1NG5IjNEJ/4+FLuuxtHd2dg5Edjfj3UgL6wIDAQAB";
        String privateKeyDaanAsBase64 = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBANKz/5fPFN6fBVCety3KbQ1w0/euWq9grY9dAX9bhvEkH05hw6fasJdbSejTKxN8KNOa4HKbH5AYfPfZu/peAYHYlxpNhJwMw8+LmhTtS9ldLuNWJOVCvbjnrQmijQ1CtkWxD6T3V/U0bkiM0Qn/j4Uu67G0d3Z2DkR2N+PdSAvrAgMBAAECgYAYKMhtRTLM5enrmQ9C4luHt4CufSDrzAeKkSz7R+jcnHo0eBRBmls2N6LtXc0qIkniHXeP3IaNdKlbl+0sY3wDjKjn270n3fk0g7IX6fd5acV/OmuuVrws/d0FJYSPyLUuuGcShuk5uIyr2KhcssiF4ulVL/jxCE2Dk+aFYtaKxQJBAOsfUG5mJyzju3GyLrvdCvqFmeaeRcMBA8Ojesjdvr58QPidJb2OvvEhmXjMycYXL70fzNdRmOSeJ4RTfwAvTD0CQQDlaZlNrzj/HNr01jblmjqxzZX0OMUhHT8/u9mKvk2aw26ZaznZD1F9jv/xcrPYMyvIQJJb7PSj+BSVkOKGvPNHAkEA2ZbvLlvnIUnXrE6DpWPYxyNg2+XZFbAYtbLS7JUZ8tq2nd2Akb5KwoifqQWMLYBDs7h8Lz/aSKh8VZ+Xxqn+2QJBAJZjfT3xyfljHx41d1NYoXWBgfXRaVjl5VqQeHF9gz4bM1ubcRab9h3LKnlLah4mnWLvAYMFePIsZMIPcpBFOW0CQGeDP/oCBAdmgIF+TLneKHijJy2xVEdIlXQzGfiYDzbzuFnlLhrtA4zM6CPlYTnBtEPGYk9s9QDcVtCV8tOtDjw=";

        byte[] publicKeyDaanAsBytes = Base64.getDecoder().decode(publicKeyDaanAsBase64);
        byte[] privateKeyDaanAsBytes = Base64.getDecoder().decode(privateKeyDaanAsBase64);

        PublicKey publicKeyDaan = kf.generatePublic(new X509EncodedKeySpec(publicKeyDaanAsBytes));
        PrivateKey privateKeyDaan = kf.generatePrivate(new PKCS8EncodedKeySpec(privateKeyDaanAsBytes));
        KeyPair keyPairDaan = new KeyPair(publicKeyDaan, privateKeyDaan);

        String publicKeyBartAsBase64 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCFm1GgJyeA+z5hUzuwpVPwvj+syKBmDhL4FwtwjSzW92m9wz0WeuGaN81DXRcn1yCbTQu18gxHmgHl8NBbtBt5Be1XdrZdfqA9OwoDL4lmo7ZJguq6YeXcp96G9p2SL5m0vHl9uz8f5BHBRm3YCpaS+gj/AFhqP4mWHgXiCLsTXQIDAQAB";
        String privateKeyBartAsBase64 = "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAIWbUaAnJ4D7PmFTO7ClU/C+P6zIoGYOEvgXC3CNLNb3ab3DPRZ64Zo3zUNdFyfXIJtNC7XyDEeaAeXw0Fu0G3kF7Vd2tl1+oD07CgMviWajtkmC6rph5dyn3ob2nZIvmbS8eX27Px/kEcFGbdgKlpL6CP8AWGo/iZYeBeIIuxNdAgMBAAECgYAbKbSypsM1Sd8o0k80XqhuLX+slS1nEj1xCt5ch5cyLSLmXacxxtHPFME6jNaEVwxeBo/28brlY743DXqO6lMbPMwQjLVtwlCmOcNqVa2Yf7ryX+5VZWegEM3U/uW4tvX6y0hUV4U619m/8qrs7yE6eMYNAZoWil/G1kckYHo+AQJBAP2JmSP3GG3vNNqN0AoGhTr23H4oeN80AX66t7EJPpnJmvG2lAD5U28y01H0G0l3tr6JSaSYaDgXyESzhcg3C30CQQCG54WXG+h2F59Felp5g4fFrLW+bInVwQt+VZOK2WzvELN5sozkILWv4hWagFq57n0Mh/l1IRJQLjnxVsRRwe1hAkAg/9HQ3o5tcJ7+e0rCo0qf/BWCzh29X3V6Wy8hecSOG7FxGIR3A/yaEpFyr0UF8PD2J8RQCg42jtHgL0WQY6m5AkAKJnNbukLUV9SpApq6F9ZoXiVSjZIVXjACMmgmg1N57VTDrFaDd56T/DvJ4yxwXuxTvAtd774UAFZlvTSKPkAhAkAbPMKfOaD8zI/7m/ZAYiY50BNMFJE/SExKYxRwRYqyK/mjCWzXnSBL2VhFlLmUjFT+BZQcMQVLANIWQJtS2hl9";

        byte[] publicKeyBartAsBytes = Base64.getDecoder().decode(publicKeyBartAsBase64);
        byte[] privateKeyBartAsBytes = Base64.getDecoder().decode(privateKeyBartAsBase64);

        PublicKey publicKeyBart = kf.generatePublic(new X509EncodedKeySpec(publicKeyBartAsBytes));
        PrivateKey privateKeyBart = kf.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBartAsBytes));
        KeyPair keyPairBart = new KeyPair(publicKeyBart, privateKeyBart);


        String publicKeyRikAsBase64 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCeTz2qXWFGn027Cdp0O2Y4cU2AkrrFuo5kgO3NsXbZU47Vcs94B8gKnqivEHIBS/ldenCGSlDSdjz3mrKu7J7OCA1IFOHI8qW3CAZVriCFRv66KaCTek+E+BHWPCvY3z1+5Zne7tV/QoayIoZsajzNJi+cTVyjWgvtfvX+l+ym7wIDAQAB";
        String privateKeyRikAsBase64 = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAJ5PPapdYUafTbsJ2nQ7ZjhxTYCSusW6jmSA7c2xdtlTjtVyz3gHyAqeqK8QcgFL+V16cIZKUNJ2PPeasq7sns4IDUgU4cjypbcIBlWuIIVG/ropoJN6T4T4EdY8K9jfPX7lmd7u1X9ChrIihmxqPM0mL5xNXKNaC+1+9f6X7KbvAgMBAAECgYAxNXl6IP+xV6huWOA+XA5owhNwwWtsNhK3+/mvhBfo8xfFkqQZ7/VHE81kaYy+iXKwk3Qx0hzwZs+Jud0MEcJE1A+nI9KoI9cVv4ZMgXsCn6FJ3AmYAmU3T5ieq7D/SLhguKgSfguc3IqXJP7s7sxKtJ/8HwxJ+yzu0YoBouJp+QJBALT8RJ8HH8ME8yKJ3txmUZbTl3j77RpkADhlhYyh+9XmVhXIenkccUKyy6T2cAwjjAb47iADDIeCLpVydgdiYhkCQQDf7OnbNMUdhEgu8yYWiq4ai7DgcNMjEEK4UpFPyqtoiVnfC4EyuQywwmr8LrCjedQWzd2iaKMjWtQZigc2QUJHAkEAise+nutJkbOj9OIfwIW9HpjV1/HmWIxCFvzSMYqsn9LmRAHc2C3VM74CplZKiSRg5Z/QiT+NRgOvUO3aT8NDUQJBAJI89rzhyZltOnbu9IDkMK/Fas4o4LqVc/1MbvndMfQjPz4bFVU65L7LOXNYSqN4fLon2Aaor2H3f2zuZ6dXFyECQGvIO2tjdrceGbCbM4gd/NRievqFmq4e1HSBgsbCQsoTdey6JjFr/QS7KnYbQwJNDmyVT/PL2zAQc95hBDcN/24=";

        byte[] publicKeyRikAsBytes = Base64.getDecoder().decode(publicKeyRikAsBase64);
        byte[] privateKeyRikAsBytes = Base64.getDecoder().decode(privateKeyRikAsBase64);

        PublicKey publicKeyRik = kf.generatePublic(new X509EncodedKeySpec(publicKeyRikAsBytes));
        PrivateKey privateKeyRik = kf.generatePrivate(new PKCS8EncodedKeySpec(privateKeyRikAsBytes));
        KeyPair keyPairRik = new KeyPair(publicKeyRik, privateKeyRik);

        keys.put("daan", keyPairDaan);
        keys.put("bart", keyPairBart);
        keys.put("rik", keyPairRik);

        return keys;
    }

    private Map<String, KeyPair> getFixedKeys2() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        Map<String, KeyPair> keys = new HashMap<>();

        keys.put("daan", getKeyPair("daan"));
        keys.put("bart", getFixedKeys().get("bart"));
        //keys.put("bart", getKeyPair("bart"));
        keys.put("rik", getKeyPair("rik"));

        return keys;
    }


    private KeyPair getKeyPair(String name) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        File publicKeyFile = new File(getClass().getClassLoader().getResource("keys/" + name + "/public.key").getFile());
        List<String> publicKeyFileLines = Files.readAllLines(publicKeyFile.toPath(), StandardCharsets.UTF_8);
        Assertions.assertEquals(1, publicKeyFileLines.size());

        File privateKeyFile = new File(getClass().getClassLoader().getResource("keys/" + name + "/private.key").getFile());
        List<String> privateKeyFileLines = Files.readAllLines(privateKeyFile.toPath(), StandardCharsets.UTF_8);
        Assertions.assertEquals(1, privateKeyFileLines.size());

        String publicKeyAsBase64 = publicKeyFileLines.get(0);
        String privateKeyAsBase64 = privateKeyFileLines.get(0);

        byte[] publicKeyAsBytes = Base64.getDecoder().decode(publicKeyAsBase64);
        byte[] privateKeyAsBytes = Base64.getDecoder().decode(privateKeyAsBase64);

        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey publicKey = kf.generatePublic(new X509EncodedKeySpec(publicKeyAsBytes));
        PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(privateKeyAsBytes));
        return new KeyPair(publicKey, privateKey);
    }
}
