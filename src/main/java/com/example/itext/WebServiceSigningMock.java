package com.example.itext;

import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Base64;

public class WebServiceSigningMock {

    private final PrivateKey privateKey;

    public WebServiceSigningMock() throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        try (InputStream inputStream = WebServiceSigningMock.class.getResourceAsStream("/security/myKeystore.pkcs12")) {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(inputStream, "".toCharArray());

            this.privateKey = (PrivateKey) keyStore.getKey("person1", "".toCharArray());
        }
    }

    public String sign(String base64ToSign) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
        byte[] hashToSign = Base64.getDecoder().decode(base64ToSign);

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(hashToSign);

        return Base64.getEncoder().encodeToString(signature.sign());
    }

}
