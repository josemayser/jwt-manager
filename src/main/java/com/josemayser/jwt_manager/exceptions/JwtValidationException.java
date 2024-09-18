package com.josemayser.jwt_manager.exceptions;

public class JwtValidationException extends Exception {
    public JwtValidationException(String message, Throwable cause) {
        super(message, cause);
    }
}