package com.josemayser.jwt_manager.exceptions.keys;

public class PublicKeyReadException extends KeysException {
    public PublicKeyReadException(Throwable cause) {
        super("Cannot get public key.", cause);
    }
}