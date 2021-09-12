package com.example.itext;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class SignaturesService {

    private Map<String, SignatureContainer> signatures = new HashMap<>();

    public void save(String key, SignatureContainer signatureContainer) {
        signatures.put(key, signatureContainer);
    }

    public Optional<SignatureContainer> getAndRemove(String key) {
        return Optional.ofNullable(signatures.get(key));
    }

}
