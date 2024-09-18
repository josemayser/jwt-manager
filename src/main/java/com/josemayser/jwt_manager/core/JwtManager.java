package com.josemayser.jwt_manager.core;

import com.josemayser.jwt_manager.domain.JwtRequest;
import com.josemayser.jwt_manager.domain.JwtResponse;
import com.josemayser.jwt_manager.exceptions.JwtDataException;
import com.josemayser.jwt_manager.exceptions.JwtGenerationException;
import com.josemayser.jwt_manager.exceptions.JwtValidationException;
import com.josemayser.jwt_manager.exceptions.keys.KeysException;
import com.josemayser.jwt_manager.exceptions.keys.PrivateKeyReadException;
import com.josemayser.jwt_manager.exceptions.keys.PublicKeyReadException;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.shaded.gson.Gson;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;
import java.util.UUID;

public class JwtManager {
    private final RsaKeyManager rsaKeyManager;
    private static JwtManager jwtManager;
    private static final String DATA_KEY = "data";

    private JwtManager() {
        rsaKeyManager = new RsaKeyManager();
    }

    public static JwtManager getInstance() {
        if (jwtManager == null) {
            jwtManager = new JwtManager();
        }
        return jwtManager;
    }

    public void initialize(
            String privateKeyPath,
            String publicKeyPath,
            Boolean generateKeysIfNotExist
    ) throws KeysException {
        rsaKeyManager.initialize(privateKeyPath, publicKeyPath);
        if (rsaKeyManager.keysExist()) {
            return;
        }
        if (!generateKeysIfNotExist) {
            throw new KeysException("Could not find keys.");
        }
        rsaKeyManager.generateKeys();
    }

    public JwtResponse generateJwt(JwtRequest<?> request) throws JwtGenerationException {
        Calendar calendar = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
        Date issueAt = new Date(calendar.getTimeInMillis());
        calendar.add(request.getExpirationTimeType().getValue(), request.getExpirationTimeAmount());
        Date expiresAt = new Date(calendar.getTimeInMillis());
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .issuer(request.getIssuer())
                .subject(request.getSubject())
                .expirationTime(expiresAt)
                .notBeforeTime(issueAt)
                .issueTime(issueAt)
                .jwtID(UUID.randomUUID().toString())
                .claim(DATA_KEY, new Gson().toJson(request.getData()))
                .build();
        try {
            RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) rsaKeyManager.getPrivateKey();
            JWSSigner jwsSigner = new RSASSASigner(rsaPrivateKey);
            JWSObject jwsObject = new JWSObject(
                    new JWSHeader(JWSAlgorithm.RS256),
                    new Payload(jwtClaimsSet.toJSONObject())
            );
            jwsObject.sign(jwsSigner);
            return new JwtResponse(jwsObject.serialize(), issueAt, expiresAt);
        } catch (PrivateKeyReadException e) {
            throw new JwtGenerationException("Could not read private key to generate JSON Web Token.", e);
        } catch (JOSEException e) {
            throw new JwtGenerationException("Could not sign JSON Web Token.", e);
        }
    }

    public String getIssuerFromJwt(String jwt) throws JwtDataException {
        try {
            return getJwtClaimsSetFromJwt(jwt).getIssuer();
        } catch (ParseException e) {
            throw new JwtDataException("Could not parse JSON Web Token.", e);
        }
    }

    public String getSubjectFromJwt(String jwt) throws JwtDataException {
        try {
            return getJwtClaimsSetFromJwt(jwt).getSubject();
        } catch (ParseException e) {
            throw new JwtDataException("Could not parse JSON Web Token.", e);
        }
    }

    public Date getIssueDateFromJwt(String jwt) throws JwtDataException {
        try {
            return getJwtClaimsSetFromJwt(jwt).getIssueTime();
        } catch (ParseException e) {
            throw new JwtDataException("Could not parse JSON Web Token.", e);
        }
    }

    public Date getExpirationDateFromJwt(String jwt) throws JwtDataException {
        try {
            return getJwtClaimsSetFromJwt(jwt).getExpirationTime();
        } catch (ParseException e) {
            throw new JwtDataException("Could not parse JSON Web Token.", e);
        }
    }

    public <Data> Data getDataFromJwt(String jwt, Class<Data> dataClass) throws JwtDataException {
        try {
            return new Gson().fromJson(getJwtClaimsSetFromJwt(jwt).getClaim(DATA_KEY).toString(), dataClass);
        } catch (ParseException e) {
            throw new JwtDataException("Could not parse JSON Web Token.", e);
        }
    }

    public Boolean jwtIsValid(String jwt) throws JwtValidationException {
        return !jwtExpired(jwt) && jwtIntegrityIsValid(jwt);
    }

    public Boolean jwtExpired(String jwt) throws JwtValidationException {
        Calendar calendar = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
        try {
            return getExpirationDateFromJwt(jwt).before(new Date(calendar.getTimeInMillis()));
        } catch (JwtDataException e) {
            throw new JwtValidationException("Failed to get JSON Web Token expiration date.", e);
        }
    }

    public Boolean jwtIntegrityIsValid(String jwt) throws JwtValidationException {
        try {
            return SignedJWT.parse(jwt).verify(new RSASSAVerifier((RSAPublicKey) rsaKeyManager.getPublicKey()));
        } catch (ParseException e) {
            throw new JwtValidationException("Could not parse JSON Web Token.", e);
        } catch (PublicKeyReadException e) {
            throw new JwtValidationException("Could not get public key to validate JSON Web Token integrity.", e);
        } catch (JOSEException e) {
            throw new JwtValidationException("Failed to verify signature to validate JSON Web Token.", e);
        }
    }

    private JWTClaimsSet getJwtClaimsSetFromJwt(String jwt) throws ParseException {
        return SignedJWT.parse(jwt).getJWTClaimsSet();
    }
}