package com.learn.gateway.config;

import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class JwtAuthenticationFilterTest {

    private JwtAuthenticationFilter filter;
    private JwtUtil jwtUtil;
    private RouteValidator routeValidator;
    private KeyPair keyPair;

    @BeforeEach
    void setUp() throws Exception {
        // Generate test RSA KeyPair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        keyPair = keyGen.generateKeyPair();

        jwtUtil = new JwtUtil(new DefaultResourceLoader());
        ReflectionTestUtils.setField(jwtUtil, "publicKey", keyPair.getPublic());

        routeValidator = new RouteValidator();
        filter = new JwtAuthenticationFilter(routeValidator, jwtUtil);
        ReflectionTestUtils.setField(filter, "jwtCookieName", "accessToken");
    }

    private String generateToken(String username, String roles, long expirationMs) {
        return Jwts.builder()
                .subject(username)
                .claim("roles", roles)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + expirationMs))
                .signWith(keyPair.getPrivate(), Jwts.SIG.RS256)
                .compact();
    }

    @Test
    void testPublicEndpointBypassesFilter() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/users/login").build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        GatewayFilterChain chain = mock(GatewayFilterChain.class);
        when(chain.filter(any(ServerWebExchange.class))).thenReturn(Mono.empty());

        StepVerifier.create(filter.filter(exchange, chain))
                .verifyComplete();

        verify(chain, times(1)).filter(exchange);
    }

    @Test
    void testSecuredEndpointWithoutTokenThrowsUnauthorized() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/users/me").build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        GatewayFilterChain chain = mock(GatewayFilterChain.class);

        StepVerifier.create(filter.filter(exchange, chain))
                .expectErrorMatches(throwable -> throwable instanceof ResponseStatusException &&
                        ((ResponseStatusException) throwable).getStatusCode() == HttpStatus.UNAUTHORIZED &&
                        "Missing authentication token".equals(((ResponseStatusException) throwable).getReason()))
                .verify();

        verify(chain, never()).filter(any(ServerWebExchange.class));
    }

    @Test
    void testSecuredEndpointWithInvalidTokenThrowsUnauthorized() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/users/me")
                .cookie(new HttpCookie("accessToken", "invalid.jwt.token"))
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        GatewayFilterChain chain = mock(GatewayFilterChain.class);

        StepVerifier.create(filter.filter(exchange, chain))
                .expectErrorMatches(throwable -> throwable instanceof ResponseStatusException &&
                        ((ResponseStatusException) throwable).getStatusCode() == HttpStatus.UNAUTHORIZED &&
                        "Invalid JWT token".equals(((ResponseStatusException) throwable).getReason()))
                .verify();

        verify(chain, never()).filter(any(ServerWebExchange.class));
    }

    @Test
    void testSecuredEndpointWithExpiredTokenThrowsUnauthorized() {
        String expiredToken = generateToken("testuser", "ROLE_USER", -10000);

        MockServerHttpRequest request = MockServerHttpRequest.get("/users/me")
                .cookie(new HttpCookie("accessToken", expiredToken))
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        GatewayFilterChain chain = mock(GatewayFilterChain.class);

        StepVerifier.create(filter.filter(exchange, chain))
                .expectErrorMatches(throwable -> throwable instanceof ResponseStatusException &&
                        ((ResponseStatusException) throwable).getStatusCode() == HttpStatus.UNAUTHORIZED &&
                        "JWT token has expired".equals(((ResponseStatusException) throwable).getReason()))
                .verify();

        verify(chain, never()).filter(any(ServerWebExchange.class));
    }

    @Test
    void testSecuredEndpointWithValidCookieMutatesHeadersAndPasses() {
        String validToken = generateToken("john_doe", "ROLE_USER,ROLE_ADMIN", 60000);

        MockServerHttpRequest request = MockServerHttpRequest.get("/users/me")
                .cookie(new HttpCookie("accessToken", validToken))
                .header("X-User-Roles", "SPOOFED_ROLE") // External attempt to spoof header
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        GatewayFilterChain chain = mock(GatewayFilterChain.class);
        ArgumentCaptor<ServerWebExchange> captor = ArgumentCaptor.forClass(ServerWebExchange.class);
        when(chain.filter(captor.capture())).thenReturn(Mono.empty());

        StepVerifier.create(filter.filter(exchange, chain))
                .verifyComplete();

        ServerWebExchange capturedExchange = captor.getValue();
        HttpHeaders headers = capturedExchange.getRequest().getHeaders();

        assertEquals("john_doe", headers.getFirst("X-User-Name"));
        assertEquals("ROLE_USER,ROLE_ADMIN", headers.getFirst("X-User-Roles"));
        assertNotEquals("SPOOFED_ROLE", headers.getFirst("X-User-Roles"));
    }

    @Test
    void testSecuredEndpointWithValidBearerHeaderPasses() {
        String validToken = generateToken("alice", "ROLE_MANAGER", 60000);

        MockServerHttpRequest request = MockServerHttpRequest.get("/users/me")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + validToken)
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        GatewayFilterChain chain = mock(GatewayFilterChain.class);
        ArgumentCaptor<ServerWebExchange> captor = ArgumentCaptor.forClass(ServerWebExchange.class);
        when(chain.filter(captor.capture())).thenReturn(Mono.empty());

        StepVerifier.create(filter.filter(exchange, chain))
                .verifyComplete();

        ServerWebExchange capturedExchange = captor.getValue();
        HttpHeaders headers = capturedExchange.getRequest().getHeaders();

        assertEquals("alice", headers.getFirst("X-User-Name"));
        assertEquals("ROLE_MANAGER", headers.getFirst("X-User-Roles"));
    }
}
