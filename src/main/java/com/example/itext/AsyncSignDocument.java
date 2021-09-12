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
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Optional;
import java.util.UUID;

public class AsyncSignDocument {

    private static final int ESTIMATED_SIGNATURE_SIZE = 8192;
    private final SignaturesService signaturesService;

    private byte[] certificateChain;
    private Certificate[] certificates;
    private String base64Signed;
    private String signatureKey;

    public AsyncSignDocument() throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        try (InputStream inputStream = AsyncSignDocument.class.getResourceAsStream("/security/myKeystore.pkcs12")) {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(inputStream, "".toCharArray());

            X509Certificate certificate = (X509Certificate) keyStore.getCertificate("person1");

            this.certificateChain = certificate.getEncoded();
            this.certificates = new Certificate[]{certificate};

            this.signaturesService = new SignaturesService();
        }
    }

    public static void main(String[] args) throws IOException, DocumentException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException, CertificateException, NoSuchProviderException, InvalidKeyException, SignatureException {
        AsyncSignDocument signDocument = new AsyncSignDocument();

        ByteArrayOutputStream output = new ByteArrayOutputStream();

        try (InputStream inputStream = AsyncSignDocument.class.getResourceAsStream("/document/example.pdf")) {
            signDocument.prepareSignature(IOUtils.toByteArray(inputStream), output);
        }

        signDocument.finish();

        File result = new File("/output/signed.pdf");
        FileUtils.writeByteArrayToFile(result, output.toByteArray());
    }

    private void finish() {
        byte[] signedHash = Base64.getDecoder().decode(base64Signed);

        Optional<SignatureContainer> signatureContainer = signaturesService.getAndRemove(signatureKey);
        signatureContainer.ifPresent(sigContainer -> {
            try {
                sigContainer.getSignining().setExternalDigest(signedHash, null, "RSA");
                byte[] encodedPKCS7 = sigContainer.getSignining().getEncodedPKCS7(
                        sigContainer.getHash(),
                        sigContainer.getAppearance().getSignDate());

                byte[] paddedSig = new byte[ESTIMATED_SIGNATURE_SIZE];

                System.arraycopy(encodedPKCS7, 0, paddedSig, 0, encodedPKCS7.length);

                PdfDictionary dictionary = new PdfDictionary();
                dictionary.put(PdfName.CONTENTS, new PdfString(paddedSig).setHexWriting(true));
                sigContainer.getAppearance().close(dictionary);
            } catch (Exception e) {
                // log.error(...)
            }
        });
    }

    public void prepareSignature(byte[] document, ByteArrayOutputStream output) throws IOException, DocumentException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, CertificateException, KeyStoreException, UnrecoverableKeyException {
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

        String base64ToSign = Base64.getEncoder().encodeToString(hashToSign);

        base64Signed = new WebServiceSigningMock().sign(base64ToSign);

        this.signatureKey = UUID.randomUUID().toString();

        SignatureContainer signatureContainer = new SignatureContainer(output, sgn, appeareanceHash, appearance);
        signaturesService.save(this.signatureKey, signatureContainer);
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

}
