package com.josemayser.jwt_manager.exceptions;

public class JwtGenerationException extends Exception {
    public JwtGenerationException(String message, Throwable cause) {
        super(message, cause);
    }
}