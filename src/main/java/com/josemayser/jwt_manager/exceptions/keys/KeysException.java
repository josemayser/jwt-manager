package com.josemayser.jwt_manager.exceptions.keys;

public class KeysException extends Exception {
    public KeysException(String message) {
        super(message);
    }

    public KeysException(String message, Throwable cause) {
        super(message, cause);
    }
}