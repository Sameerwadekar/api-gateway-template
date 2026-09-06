package com.learn.gateway.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Slf4j
@Component
public class JwtUtil {

    @Value("${spring.app.jwt.public-key-path:keys/public.pem}")
    private String publicKeyPath;

    private final ResourceLoader resourceLoader;
    private PublicKey publicKey;

    public JwtUtil(ResourceLoader resourceLoader) {
        this.resourceLoader = resourceLoader;
    }

    @PostConstruct
    public void init() {
        try {
            this.publicKey = loadPublicKey(publicKeyPath);
            log.info("JWT RSA Public Key loaded successfully from: {}", publicKeyPath);
        } catch (Exception e) {
            log.error("Failed to load JWT RSA Public Key from path: {}", publicKeyPath, e);
            throw new IllegalStateException("Could not initialize JWT Public Key", e);
        }
    }

    /**
     * Validates the JWT token using the loaded RSA public key and returns the Claims payload.
     * Throws ExpiredJwtException if the token is expired, or JwtException for any tampering/malformation.
     */
    public Claims validateAndGetClaims(String token) throws ExpiredJwtException, JwtException {
        return Jwts.parser()
                .verifyWith(publicKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private PublicKey loadPublicKey(String pathStr) throws Exception {
        String key = readKeyContent(pathStr);
        key = key
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replace("-----BEGIN RSA PUBLIC KEY-----", "")
                .replace("-----END RSA PUBLIC KEY-----", "")
                .replaceAll("\\s+", "");

        byte[] decoded = Base64.getDecoder().decode(key);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(spec);
    }

    private String readKeyContent(String pathStr) throws Exception {
        if (pathStr == null || pathStr.isBlank()) {
            throw new IllegalArgumentException("Public key path must not be null or empty");
        }

        // 1. If raw PEM is passed directly
        if (pathStr.contains("-----BEGIN")) {
            return pathStr;
        }

        // 2. Try direct file path (e.g. keys/public.pem from root)
        Path path = Path.of(pathStr);
        if (Files.exists(path)) {
            return Files.readString(path);
        }

        // 3. Try ResourceLoader (file: / classpath:)
        String location = pathStr.startsWith("classpath:") || pathStr.startsWith("file:") ? pathStr : "file:" + pathStr;
        Resource resource = resourceLoader.getResource(location);
        if (resource.exists()) {
            try (InputStream is = resource.getInputStream()) {
                return new String(is.readAllBytes(), StandardCharsets.UTF_8);
            }
        }

        // 4. Try fallback to classpath
        Resource classpathResource = resourceLoader.getResource("classpath:" + pathStr);
        if (classpathResource.exists()) {
            try (InputStream is = classpathResource.getInputStream()) {
                return new String(is.readAllBytes(), StandardCharsets.UTF_8);
            }
        }

        // 5. Try fallback classpath with /keys/public.pem
        Resource fallbackClasspath = resourceLoader.getResource("classpath:/keys/public.pem");
        if (fallbackClasspath.exists()) {
            try (InputStream is = fallbackClasspath.getInputStream()) {
                return new String(is.readAllBytes(), StandardCharsets.UTF_8);
            }
        }

        throw new IllegalArgumentException("Public key file not found at path: " + pathStr);
    }
}
