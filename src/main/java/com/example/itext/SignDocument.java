package com.example.itext;

import com.lowagie.text.DocumentException;
import com.lowagie.text.Rectangle;
import com.lowagie.text.pdf.PdfDate;
import com.lowagie.text.pdf.PdfDictionary;
import com.lowagie.text.pdf.PdfName;
import com.lowagie.text.pdf.PdfPKCS7;
import com.lowagie.text.pdf.PdfReader;
import com.lowagie.text.pdf.PdfSignature;
import com.lowagie.text.pdf.PdfSignatureAppearance;
import com.lowagie.text.pdf.PdfStamper;
import com.lowagie.text.pdf.PdfString;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.HashMap;

public class SignDocument {

    private static final int ESTIMATED_SIGNATURE_SIZE = 8192;

    private byte[] certificateChain;
    private Certificate[] certificates;
    private PrivateKey privateKey;

    public SignDocument() throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        try (InputStream inputStream = SignDocument.class.getResourceAsStream("/security/myKeystore.pkcs12")) {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(inputStream, "".toCharArray());

            X509Certificate certificate = (X509Certificate) keyStore.getCertificate("person1");

            this.privateKey = (PrivateKey) keyStore.getKey("person1", "".toCharArray());
            this.certificateChain = certificate.getEncoded();
            this.certificates = new Certificate[]{certificate};
        }
    }

    public static void main(String[] args) throws IOException, DocumentException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException, CertificateException, NoSuchProviderException, InvalidKeyException, SignatureException {
        SignDocument signDocument = new SignDocument();

        ByteArrayOutputStream output = new ByteArrayOutputStream();

        try (InputStream inputStream = SignDocument.class.getResourceAsStream("/document/example.pdf")) {

            signDocument.sign(IOUtils.toByteArray(inputStream), output);
        }

        File result = new File("/output/signed.pdf");
        FileUtils.writeByteArrayToFile(result, output.toByteArray());
    }

    public void sign(byte[] document, ByteArrayOutputStream output) throws IOException, DocumentException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        PdfReader pdfReader = new PdfReader(document);

        PdfStamper signer = PdfStamper.createSignature(pdfReader, output, '\0');

        Calendar signDate = Calendar.getInstance();

        int page = 1;

        PdfSignature pdfSignature = new PdfSignature(PdfName.ADOBE_PPKLITE, PdfName.ADBE_PKCS7_DETACHED);
        pdfSignature.setReason("Reason to sign");
        pdfSignature.setLocation("Location of signature");
        pdfSignature.setContact("Person Name");
        pdfSignature.setDate(new PdfDate(signDate));
        pdfSignature.setCert(certificateChain);

        PdfSignatureAppearance appearance = createAppearance(signer, page, pdfSignature);

        PdfPKCS7 sgn = new PdfPKCS7(null, certificates, null, "SHA-256", null, false);
        InputStream data = appearance.getRangeStream();

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(IOUtils.toByteArray(data));
        byte[] appeareanceHash = digest.digest();

        byte[] hashToSign = sgn.getAuthenticatedAttributeBytes(appeareanceHash, appearance.getSignDate(), null);

        byte[] signedHash = addDigitalSignatureToHash(hashToSign);

        sgn.setExternalDigest(signedHash, null, "RSA");
        byte[] encodedPKCS7 = sgn.getEncodedPKCS7(appeareanceHash, appearance.getSignDate());

        byte[] paddedSig = new byte[ESTIMATED_SIGNATURE_SIZE];

        System.arraycopy(encodedPKCS7, 0, paddedSig, 0, encodedPKCS7.length);

        PdfDictionary dictionary = new PdfDictionary();
        dictionary.put(PdfName.CONTENTS, new PdfString(paddedSig).setHexWriting(true));
        appearance.close(dictionary);
    }

    private PdfSignatureAppearance createAppearance(PdfStamper signer, int page, PdfSignature pdfSignature) throws IOException, DocumentException {
        PdfSignatureAppearance appearance = signer.getSignatureAppearance();
        appearance.setRender(PdfSignatureAppearance.SignatureRenderDescription);
        appearance.setAcro6Layers(true);

        int lowerLeftX = 570;
        int lowerLeftY = 70;
        int width = 370;
        int height = 150;
        appearance.setVisibleSignature(new Rectangle(lowerLeftX, lowerLeftY, width, height), page, null);

        appearance.setCryptoDictionary(pdfSignature);
        appearance.setCrypto(null, certificates, null, PdfName.FILTER);

        HashMap<Object, Object> exclusions = new HashMap<>();
        exclusions.put(PdfName.CONTENTS, ESTIMATED_SIGNATURE_SIZE * 2 + 2);
        appearance.preClose(exclusions);

        return appearance;
    }

    public byte[] addDigitalSignatureToHash(byte[] hashToSign) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(hashToSign);

        return signature.sign();
    }

}
