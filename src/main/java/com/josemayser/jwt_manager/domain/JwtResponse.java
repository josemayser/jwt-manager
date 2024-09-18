package com.josemayser.jwt_manager.domain;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.util.Date;

@AllArgsConstructor
@Getter
@Setter
public class JwtResponse {
    private String token;
    private Date issuedAt;
    private Date expiresAt;
}