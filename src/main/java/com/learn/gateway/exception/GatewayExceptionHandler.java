package com.learn.gateway.exception;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.learn.gateway.dto.ErrorResponse;
import org.springframework.boot.web.reactive.error.ErrorWebExceptionHandler;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.ConnectException;
import java.util.UUID;

@Component
@Order(-1)
public class GatewayExceptionHandler implements ErrorWebExceptionHandler {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public Mono<Void> handle(ServerWebExchange exchange, Throwable ex) {
        ServerHttpResponse response = exchange.getResponse();

        if (response.isCommitted()) {
            return Mono.error(ex);
        }

        HttpStatus status = HttpStatus.INTERNAL_SERVER_ERROR;
        String message = "An unexpected gateway error occurred.";

        if (ex instanceof ConnectException) {
            // Downstream service is completely dead
            status = HttpStatus.SERVICE_UNAVAILABLE;
            message = "The requested downstream service is currently unavailable.";
        } else if (ex instanceof ResponseStatusException) {
            // Handles built-in WebFlux status exceptions (like 404 route not found)
            status = HttpStatus.valueOf(((ResponseStatusException) ex).getStatusCode().value());
            message = ((ResponseStatusException) ex).getReason();
        }

        // 2. Build your standardized error JSON object
        response.setStatusCode(status);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        String path = exchange.getRequest().getPath().value();
        String traceId = UUID.randomUUID().toString(); // Replace with actual Micrometer/Sleuth trace ID if available

        ErrorResponse errorResponse = new ErrorResponse(status.value(), message, path, traceId);

        // 3. Write JSON response back asynchronously
        try {
            byte[] bytes = objectMapper.writeValueAsBytes(errorResponse);
            DataBuffer buffer = response.bufferFactory().wrap(bytes);
            return response.writeWith(Mono.just(buffer));
        } catch (JsonProcessingException e) {
            return Mono.error(e);
        }
    }
}
