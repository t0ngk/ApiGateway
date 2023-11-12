package com.t0ng.apigateway;

import io.jsonwebtoken.Claims;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@RefreshScope
@Component
public class AuthenticationFliter implements GlobalFilter {
    private final RouterValidator routerValidator;
    private final JwtUtil jwtUtil;

    public AuthenticationFliter(RouterValidator routerValidator, JwtUtil jwtUtil) {
        this.routerValidator = routerValidator;
        this.jwtUtil = jwtUtil;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();

        if (routerValidator.isSecured.test(request)) {
            if (this.isAuthMissing(request)) {
                return this.onError(exchange, "Authorization header is missing in request", HttpStatus.UNAUTHORIZED);
            }

            final String header = this.getAuthHeader(request);
            if (!header.startsWith("Bearer ")) {
                return this.onError(exchange, "Authorization header is not valid", HttpStatus.UNAUTHORIZED);
            }

            final String token = header.substring("Bearer ".length());

            if (jwtUtil.isInvalid(token)) {
                return this.onError(exchange, "Authorization header is not valid", HttpStatus.UNAUTHORIZED);
            }

            this.populateRequestWithHeader(exchange, token);
        }
        return chain.filter(exchange);
    }

    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        return response.setComplete();
    }

    private String getAuthHeader(ServerHttpRequest request) {
        return request.getHeaders().getOrEmpty("Authorization").get(0);
    }

    private boolean isAuthMissing(ServerHttpRequest request) {
        return !request.getHeaders().containsKey("Authorization");
    }

    private void populateRequestWithHeader(ServerWebExchange exchange, String token) {
        Claims claims = jwtUtil.getAllClaimsFromToken(token);
        System.out.println("Claims: " + claims);
        exchange.getRequest()
                .mutate()
                .header("userId", String.valueOf(claims.get("_id")))
                .header("username", String.valueOf(claims.get("username")))
                .header("role", String.valueOf(claims.get("role")))
                .build();
    }
}
