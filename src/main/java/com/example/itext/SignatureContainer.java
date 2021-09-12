package com.example.itext;

import com.lowagie.text.pdf.PdfPKCS7;
import com.lowagie.text.pdf.PdfSignatureAppearance;

import java.io.ByteArrayOutputStream;

public class SignatureContainer {

    private ByteArrayOutputStream outputStream;

    private PdfPKCS7 signining;

    private byte[] hash;

    private PdfSignatureAppearance appearance;

    public SignatureContainer(ByteArrayOutputStream outputStream, PdfPKCS7 signining, byte[] hash, PdfSignatureAppearance appearance) {
        this.outputStream = outputStream;
        this.signining = signining;
        this.hash = hash;
        this.appearance = appearance;
    }

    public ByteArrayOutputStream getOutputStream() {
        return outputStream;
    }

    public PdfPKCS7 getSignining() {
        return signining;
    }

    public byte[] getHash() {
        return hash;
    }

    public PdfSignatureAppearance getAppearance() {
        return appearance;
    }
}
