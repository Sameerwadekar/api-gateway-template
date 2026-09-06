package com.learn.gateway.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Slf4j
@Component
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    @Value("${spring.app.jwtCookieName:accessToken}")
    private String jwtCookieName;

    private final RouteValidator routeValidator;
    private final JwtUtil jwtUtil;

    public JwtAuthenticationFilter(RouteValidator routeValidator, JwtUtil jwtUtil) {
        this.routeValidator = routeValidator;
        this.jwtUtil = jwtUtil;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();

        // Step 1: Check if endpoint is public/whitelisted
        if (!routeValidator.isSecured(request)) {
            return chain.filter(exchange);
        }

        // Step 2: Extract token (Cookie first, Bearer header fallback)
        String token = extractToken(request);
        if (token == null || token.isBlank()) {
            log.warn("Access denied: Missing authentication token for path: {}", request.getURI().getPath());
            return Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Missing authentication token"));
        }

        // Step 3: Validate token signature and expiry using RSA public key
        Claims claims;
        try {
            claims = jwtUtil.validateAndGetClaims(token);
        } catch (ExpiredJwtException e) {
            log.warn("Access denied: JWT token expired for path: {}", request.getURI().getPath());
            return Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED, "JWT token has expired"));
        } catch (Exception e) {
            log.warn("Access denied: Invalid JWT token ({}) for path: {}", e.getMessage(), request.getURI().getPath());
            return Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid JWT token"));
        }

        // Step 4: Extract user info from claims
        String username = claims.getSubject();
        String roles = claims.get("roles", String.class);

        // Step 5: Sanitize and enrich request headers for downstream microservices
        ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                .headers(httpHeaders -> {
                    // Prevent header spoofing from untrusted external clients
                    httpHeaders.remove("X-User-Name");
                    httpHeaders.remove("X-User-Roles");
                })
                .header("X-User-Name", username != null ? username : "")
                .header("X-User-Roles", roles != null ? roles : "")
                .build();

        // Step 6: Forward mutated request down the filter chain
        return chain.filter(exchange.mutate().request(mutatedRequest).build());
    }

    /**
     * Extracts JWT token from the request.
     * Checks HttpOnly cookie first, then falls back to Authorization header.
     */
    private String extractToken(ServerHttpRequest request) {
        // 1. Look for cookie (e.g. accessToken)
        HttpCookie cookie = request.getCookies().getFirst(jwtCookieName);
        if (cookie != null && !cookie.getValue().isBlank()) {
            return cookie.getValue();
        }

        // 2. Look for Bearer token in Authorization header
        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7).trim();
        }

        return null;
    }

    @Override
    public int getOrder() {
        return -5; // Execute early in the gateway filter chain
    }
}
