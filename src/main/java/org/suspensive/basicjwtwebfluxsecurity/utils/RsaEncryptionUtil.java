package org.suspensive.basicjwtwebfluxsecurity.utils;

import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

@Component
public class RsaEncryptionUtil {

    private final Cipher cipher;

    private final KeyPair keyPair;

    public RsaEncryptionUtil() throws NoSuchPaddingException, NoSuchAlgorithmException {
        this.cipher = Cipher.getInstance("RSA");

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        this.keyPair = keyPairGenerator.generateKeyPair();

    }

    public String decrypt(String encryptedText) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        this.cipher.init(Cipher.DECRYPT_MODE,getPrivateKey());

        return new String(this.cipher.doFinal(Base64.getDecoder().decode(encryptedText)), StandardCharsets.UTF_8);
    }

    public String encrypt(String plainText) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        this.cipher.init(Cipher.ENCRYPT_MODE,getPublicKey());
        return Base64.getEncoder().encodeToString(this.cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8)));
    }

    @Bean
    public Algorithm getTokenAlgorithm(){
        return Algorithm.RSA256((RSAPublicKey) getPublicKey(), (RSAPrivateKey) getPrivateKey());
    }

    private PrivateKey getPrivateKey() {
        return this.keyPair.getPrivate();
    }

    public PublicKey getPublicKey(){
        return this.keyPair.getPublic();
    }
}
