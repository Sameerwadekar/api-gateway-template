package com.learn.gateway.config;

import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import reactor.core.publisher.Mono;

@Configuration
public class RateLimiterConfig {
    @Bean
    public KeyResolver ipKeyResolver() {
        return exchange -> {
            String clientIp = exchange.getRequest().getHeaders().getFirst("X-Forwarded-For");
            if (clientIp != null && !clientIp.isBlank()) {
                return Mono.just(clientIp.split(",")[0].trim());
            }

            if (exchange.getRequest().getRemoteAddress() != null &&
                    exchange.getRequest().getRemoteAddress().getAddress() != null) {
                return Mono.just(exchange.getRequest().getRemoteAddress().getAddress().getHostAddress());
            }

            return Mono.just("anonymous");
        };
    }
}
