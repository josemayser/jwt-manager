package com.josemayser.jwt_manager.exceptions.keys;

public class PrivateKeyReadException extends KeysException {
    public PrivateKeyReadException(Throwable cause) {
        super("Cannot get private key.", cause);
    }
}