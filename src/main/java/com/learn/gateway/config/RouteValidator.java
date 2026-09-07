package com.learn.gateway.config;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import java.util.List;

@Component
public class RouteValidator {

    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    public static final List<String> OPEN_API_ENDPOINTS = List.of(
            "/users/register",
            "/users/login",
            "/users/refresh",
            "/auth/public-key",
            "/health",
            "/actuator/**",
            "/eureka/**",
            "/api/auth/**",
            "/api/v1/auth/**"
    );

    public boolean isSecured(ServerHttpRequest request) {
        String path = request.getURI().getPath();
        return OPEN_API_ENDPOINTS.stream()
                .noneMatch(pattern -> pathMatcher.match(pattern, path));
    }
}