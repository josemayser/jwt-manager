package com.josemayser.jwt_manager.domain;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class JwtRequest<Data> {
    private String issuer;
    private String subject;
    private ExpirationTimeType expirationTimeType;
    private Integer expirationTimeAmount;
    private Data data;
}