package com.krooj.oauth.common.util;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.krooj.oauth.common.domain.OAuthToken;
import com.krooj.oauth.common.domain.Token;
import com.krooj.oauth.common.domain.TokenType;
import com.krooj.oauth.common.exception.OAuthServiceException;
import org.springframework.util.Base64Utils;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Base64;

/**
 * Singleton helper for encryption
 */
public final class CryptoUtil {

    private static volatile CryptoUtil instance = new CryptoUtil();

    private final SecretKeySpec secretKeySpec;

    private final ObjectMapper objectMapper;

    private CryptoUtil() {
        try (BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(CryptoUtil.class.getResourceAsStream("/token.key")))) {
            String symmetricKey = bufferedReader.readLine();
            InputValidationUtils.assertHasText(symmetricKey, "error.tokenservices.key");
            byte[] decodedKey = Base64Utils.decodeFromString(symmetricKey);
            this.secretKeySpec = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
            this.objectMapper = new ObjectMapper();
        } catch (IOException e) {
            throw new OAuthServiceException("error.keypath", e);
        }
    }

    public static CryptoUtil getInstance() {
        return instance;
    }

    public String tokenToBase64CipherText(Token token) throws OAuthServiceException {
        try {
            String accessTokenJson = this.objectMapper.writeValueAsString(token);
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "SunJCE");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
            String base64EncodedToken = Base64.getUrlEncoder().encodeToString(cipher.doFinal(accessTokenJson.getBytes("UTF-8")));
            System.out.println(base64EncodedToken);
            return base64EncodedToken;
        } catch (JsonProcessingException e) {
            throw new OAuthServiceException("error.tokenservices.serialization", e);
        } catch (IllegalBlockSizeException | InvalidKeyException | BadPaddingException | NoSuchAlgorithmException | NoSuchPaddingException | NoSuchProviderException | UnsupportedEncodingException e) {
            throw new OAuthServiceException("error.tokenservices.encryption", e);
        }
    }

    public Token base64CipherTexttoToken(String tokenCipherText, TokenType tokenType) throws OAuthServiceException {
        InputValidationUtils.assertHasText(tokenCipherText, "token.empty");

        //Decrypt the ciphertext
        try {
            byte[] cipherBytes = Base64.getUrlDecoder().decode(tokenCipherText);
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "SunJCE");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
            byte[] decipheredBytes = cipher.doFinal(cipherBytes);
            String jsonToken = new String(decipheredBytes);
            Token decryptedToken = null;
            switch (tokenType) {
                case ACCESS_TOKEN:
                case REFRESH_TOKEN:
                case AUTHORIZATION_CODE:
                    decryptedToken = objectMapper.readValue(jsonToken, OAuthToken.class);
                    break;
                default:
                    throw new OAuthServiceException("error.tokenservices.decryption.unknown");
            }
            return decryptedToken;
        } catch (IllegalBlockSizeException | InvalidKeyException | BadPaddingException | NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException e) {
            throw new OAuthServiceException("error.tokenservices.decryption.cipher", e);
        } catch (JsonMappingException | JsonParseException e) {
            throw new OAuthServiceException("error.tokenservices.decryption.json", e);
        } catch (IOException e) {
            throw new OAuthServiceException("error.tokenservices.decryption.io", e);
        }
    }

}
