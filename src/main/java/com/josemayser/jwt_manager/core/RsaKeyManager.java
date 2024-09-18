package com.josemayser.jwt_manager.core;

import com.josemayser.jwt_manager.exceptions.keys.*;

import java.io.*;
import java.security.*;

class RsaKeyManager {
    private String privateKeyPath;
    private String publicKeyPath;

    public void initialize(String privateKeyPath, String publicKeyPath) throws KeysException {
        if (privateKeyPath == null || privateKeyPath.isBlank()) {
            throw new KeysException("The private key path must not be null or empty.");
        }
        if (publicKeyPath == null || publicKeyPath.isBlank()) {
            throw new KeysException("The public key path must not be null or empty.");
        }
        this.privateKeyPath = privateKeyPath;
        this.publicKeyPath = publicKeyPath;
    }

    public Boolean keysExist() {
        return new File(privateKeyPath).exists() && new File(publicKeyPath).exists();
    }

    public void generateKeys() throws KeysGenerationException {
        File privateKeyFile = generatePrivateKeyFile();
        File publicKeyFile = generatePublicKeyFile();
        try {
            final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            final KeyPair keyPair = keyPairGenerator.generateKeyPair();
            ObjectOutputStream privateKeyOos = new ObjectOutputStream(new FileOutputStream(privateKeyFile));
            privateKeyOos.writeObject(keyPair.getPrivate());
            privateKeyOos.close();
            ObjectOutputStream publicKeyOos = new ObjectOutputStream(new FileOutputStream(publicKeyFile));
            publicKeyOos.writeObject(keyPair.getPublic());
            publicKeyOos.close();
        } catch (NoSuchAlgorithmException | IOException e) {
            throw new KeysGenerationException(e);
        }
    }

    public PrivateKey getPrivateKey() throws PrivateKeyReadException {
        try {
            return (PrivateKey) new ObjectInputStream(new FileInputStream(privateKeyPath)).readObject();
        } catch (IOException | ClassNotFoundException e) {
            throw new PrivateKeyReadException(e);
        }
    }

    public PublicKey getPublicKey() throws PublicKeyReadException {
        try {
            return (PublicKey) new ObjectInputStream(new FileInputStream(publicKeyPath)).readObject();
        } catch (IOException | ClassNotFoundException e) {
            throw new PublicKeyReadException(e);
        }
    }

    private File generatePrivateKeyFile() throws PrivateKeyGenerationException {
        File privateKeyFile = new File(privateKeyPath);
        File parentFile = privateKeyFile.getParentFile();
        if (parentFile != null && !parentFile.exists() && !parentFile.mkdirs()) {
            throw new PrivateKeyGenerationException();
        }
        try {
            if (!privateKeyFile.createNewFile()) {
                throw new PrivateKeyGenerationException();
            }
        } catch (IOException e) {
            throw new PrivateKeyGenerationException(e);
        }
        return privateKeyFile;
    }

    private File generatePublicKeyFile() throws PublicKeyGenerationException {
        File publicKeyFile = new File(publicKeyPath);
        File parentFile = publicKeyFile.getParentFile();
        if (parentFile != null && !parentFile.exists() && !parentFile.mkdirs()) {
            throw new PublicKeyGenerationException();
        }
        try {
            if (!publicKeyFile.createNewFile()) {
                throw new PublicKeyGenerationException();
            }
        } catch (IOException e) {
            throw new PublicKeyGenerationException(e);
        }
        return publicKeyFile;
    }
}