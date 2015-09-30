package com.krooj.oauth.common.util;

/**
 * Created by michaelkuredjian on 9/26/15.
 */
public class KeyPairGenerationUtil {

//    public static void main(String... args) throws Exception {
//        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
//        kpg.initialize(2048);
//        KeyPair kp = kpg.genKeyPair();
//        Key publicKey = kp.getPublic();
//        Key privateKey = kp.getPrivate();
//
//        KeyFactory fact = KeyFactory.getInstance("RSA");
//        RSAPublicKeySpec pub = fact.getKeySpec(kp.getPublic(),
//                RSAPublicKeySpec.class);
//        RSAPrivateKeySpec priv = fact.getKeySpec(kp.getPrivate(),
//                RSAPrivateKeySpec.class);
//
//        saveToFile("tokenKey.pub.key", pub.getModulus(),
//                pub.getPublicExponent());
//        saveToFile("tokenKey.prv.key", priv.getModulus(),
//                priv.getPrivateExponent());
//    }
//
//    public static void saveToFile(String fileName,
//                                  BigInteger mod, BigInteger exp) throws IOException {
//        ObjectOutputStream oout = new ObjectOutputStream(
//                new BufferedOutputStream(new FileOutputStream(fileName)));
//        try {
//            oout.writeObject(mod);
//            oout.writeObject(exp);
//        } catch (Exception e) {
//            throw new IOException("Unexpected error", e);
//        } finally {
//            oout.close();
//        }
//    }

//    public static void main(String... args) throws Exception{
//        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
//        keyGenerator.init(128);
//        SecretKey key = keyGenerator.generateKey();
//        String encodedKey = Base64.getEncoder().encodeToString(key.getEncoded());
//        System.out.println(encodedKey);
//    }

}
