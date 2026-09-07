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

        if (!routeValidator.isSecured(request)) {
            return chain.filter(exchange);
        }

        String token = extractToken(request);
        if (token == null || token.isBlank()) {
            log.warn("Access denied: Missing authentication token for path: {}", request.getURI().getPath());
            return Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Missing authentication token"));
        }

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

        String username = claims.getSubject();
        String roles = claims.get("roles", String.class);

        ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                .headers(httpHeaders -> {
                    httpHeaders.remove("X-User-Name");
                    httpHeaders.remove("X-User-Roles");
                })
                .header("X-User-Name", username != null ? username : "")
                .header("X-User-Roles", roles != null ? roles : "")
                .build();
        return chain.filter(exchange.mutate().request(mutatedRequest).build());
    }

    private String extractToken(ServerHttpRequest request) {
        HttpCookie cookie = request.getCookies().getFirst(jwtCookieName);
        if (cookie != null && !cookie.getValue().isBlank()) {
            return cookie.getValue();
        }

        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7).trim();
        }

        return null;
    }

    @Override
    public int getOrder() {
        return -5;
    }
}
