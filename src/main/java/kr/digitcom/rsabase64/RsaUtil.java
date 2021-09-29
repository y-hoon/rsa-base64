package kr.digitcom.rsabase64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RsaUtil {

    /**
     * 2048 바이트 RSA keypair 생성
     * @return KeyPair
     * @throws NoSuchAlgorithmException 알고리즘을 지원하지 않는 경우
     */
    public static KeyPair genRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
        rsaGen.initialize(2048, new SecureRandom());

        return rsaGen.genKeyPair();
    }

    /**
     * base64 encoding된 PublicKey를 다시 PublicKey로 생성함
     * @param base64PublicKey base64 encoding된 PublicKey
     * @return PublicKey
     * @throws NoSuchAlgorithmException exception
     * @throws InvalidKeySpecException exception
     */
    public static PublicKey getPublicKeyFromBase64Encrypted(String base64PublicKey)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] decodedBase64PubKey = Base64.getDecoder().decode(base64PublicKey);

        return KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(decodedBase64PubKey));
    }

    /**
     * RSA 암호화를 하고 BASE64 인코딩을 진행함
     *
     * @param plainText 암호화 대상 문자열(평문)
     * @param publicKey 공개키
     * @return 암호화 결과
     * @throws NoSuchPaddingException exception
     * @throws NoSuchAlgorithmException exception
     * @throws InvalidKeyException exception
     * @throws BadPaddingException exception
     * @throws IllegalBlockSizeException exception
     */
    public static String encryptRSA(String plainText, PublicKey publicKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] bytePlainText = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(bytePlainText);
    }
}
