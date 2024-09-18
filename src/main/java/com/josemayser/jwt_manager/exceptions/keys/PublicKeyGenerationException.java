package com.josemayser.jwt_manager.exceptions.keys;

public class PublicKeyGenerationException extends KeysGenerationException {
    public PublicKeyGenerationException() {
        super("Could not generate public key.");
    }

    public PublicKeyGenerationException(Throwable cause) {
        super("Could not generate public key.", cause);
    }
}