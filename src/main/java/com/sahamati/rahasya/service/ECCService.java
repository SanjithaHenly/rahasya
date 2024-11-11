package com.sahamati.rahasya.service;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.KeyAgreement;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.springframework.stereotype.Service;

@Service
public class ECCService {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public Map<String, String> generateKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
            keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());

            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            String publicKey = Base64.toBase64String(keyPair.getPublic().getEncoded());
            String privateKey = Base64.toBase64String(keyPair.getPrivate().getEncoded());

            Map<String, String> keyPairMap = new HashMap<>();
            keyPairMap.put("publicKey", publicKey);
            keyPairMap.put("privateKey", privateKey);

            return keyPairMap;
        } catch (Exception e) {
            throw new RuntimeException("Error generating ECC key pair", e);
        }
    }

    public String generateSharedKey(String remotePublicKeyBase64, String ourPrivateKeyBase64) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");

            byte[] remotePublicKeyBytes = Base64.decode(remotePublicKeyBase64);
            PublicKey remotePublicKey = keyFactory.generatePublic(new X509EncodedKeySpec(remotePublicKeyBytes));

            byte[] ourPrivateKeyBytes = Base64.decode(ourPrivateKeyBase64);
            PrivateKey ourPrivateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(ourPrivateKeyBytes));

            KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", "BC");
            keyAgreement.init(ourPrivateKey);
            keyAgreement.doPhase(remotePublicKey, true);

            byte[] sharedSecret = keyAgreement.generateSecret();
            return Base64.toBase64String(sharedSecret);

        } catch (Exception e) {
            throw new RuntimeException("Error generating shared key", e);
        }
    }

    public String encryptData(String remoteKeyMaterial, String ourPrivateKey, String base64RemoteNonce, String base64YourNonce, String data) {
        // Encrypt data here using provided keys, nonces, and data.
        // For illustration only. Implement an ECC-compatible encryption algorithm like AES with ECDH for shared secret derivation.
        throw new UnsupportedOperationException("Encryption method not yet implemented");
    }

    public String decryptData(String remoteKeyMaterial, String ourPrivateKey, String base64RemoteNonce, String base64YourNonce, String base64Data) {
        // Decrypt data here using provided keys, nonces, and data.
        // For illustration only. Implement decryption in alignment with the chosen encryption method in `encryptData`.
        throw new UnsupportedOperationException("Decryption method not yet implemented");
    }
}
