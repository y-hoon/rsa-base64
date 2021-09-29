package kr.digitcom.rsabase64;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.DigestUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

@Slf4j
@RestController
public class RsaBase64Controller {

    //base64 string은 web에서 변환
    // https://www.base64-image.de/
    @PostMapping("/image/base64")
    public ResponseEntity<String> fileToBase64(@RequestParam("signatureCaptureFile")MultipartFile signatureFile) {

        String encodedString = null;
        try {
            byte[] signatureFileBytes = signatureFile.getBytes();
            encodedString = Base64.getEncoder().encodeToString(signatureFileBytes);

        } catch (IOException e) {
            e.printStackTrace();
        }

        return new ResponseEntity<>(encodedString, HttpStatus.OK);
    }

    @PostMapping("/rsa/encoder")
    public ResponseEntity<String> rsaEncoder(@RequestParam("signatureCaptureFileBase64") String base64str,
                                             @RequestParam("rsaPublicKey") String rsaPublicKey) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {

        //key 식별
        PublicKey publicKey = RsaUtil.getPublicKeyFromBase64Encrypted(rsaPublicKey);

        //base64를 MD5 Hash
        String md5HashBase64 = DigestUtils.md5DigestAsHex(base64str.getBytes());

        //암호화
        String encryptRSAStr = RsaUtil.encryptRSA(md5HashBase64, publicKey);

        log.info("baes64 string RSA encoding : [{}]", encryptRSAStr);

        return new ResponseEntity<>(encryptRSAStr, HttpStatus.OK);

    }
}
