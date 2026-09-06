package com.learn.gateway.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Data
public class ErrorResponse {
    private int status;
    private String message;
    private long timestamp;
    private String path;
    private String traceId;

    public ErrorResponse(int status, String message, String path, String traceId) {
        this.status = status;
        this.message = message;
        this.timestamp = System.currentTimeMillis();
        this.path = path;
        this.traceId = traceId;
    }
}
