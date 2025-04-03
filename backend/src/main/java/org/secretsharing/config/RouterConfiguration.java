package org.secretsharing.config;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.NoSuchElementException;
import java.util.logging.Level;

import org.secretsharing.model.SecretShareDTO;
import org.secretsharing.service.SecretSharing;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.reactive.function.server.RequestPredicates;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;

import lombok.extern.java.Log;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import org.springdoc.core.annotations.RouterOperation;
import org.springdoc.core.annotations.RouterOperations;

@Log
@CrossOrigin(origins = "*")
@Configuration
public class RouterConfiguration {

    @Autowired
    private SecretSharing secretSharing;

    @RouterOperations({
            @RouterOperation(path = "/api/v1/splitSecret", method = RequestMethod.GET, 
                produces = MediaType.APPLICATION_JSON_VALUE, beanClass = SecretSharing.class, beanMethod = "splitSecret"),
            @RouterOperation(path = "/api/v1/recoverSecret", method = RequestMethod.POST, 
                consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.TEXT_PLAIN_VALUE, beanClass = SecretSharing.class, beanMethod = "recoverSecret") })

    @Bean
    RouterFunction<ServerResponse> secretSharingRoutes() {
        return RouterFunctions.route()
                .GET("/api/v1/splitSecret",
                        RequestPredicates.all()
                                .and(RequestPredicates.method(HttpMethod.GET)),
                        this::splitSecretHandler)
                .POST("/api/v1/recoverSecret",
                        RequestPredicates.all()
                                .and(RequestPredicates.method(HttpMethod.POST)),
                        this::recoverSecretHandler)
                .build();
    }

    private Mono<ServerResponse> splitSecretHandler(ServerRequest request) {

        int k = Integer.parseInt(request.queryParam("k").orElseThrow());
        int n = Integer.parseInt(request.queryParam("n").orElseThrow());
        String secret = request.queryParam("secret").orElseThrow();

        try {
            Flux<SecretShareDTO> sharesFlux = secretSharing.splitSecret(k, n, secret);
            return ServerResponse.ok()
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(sharesFlux, SecretShareDTO.class)
                    .onErrorResume(NoSuchElementException.class, this::handleException);
        } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException ex) {
            return handleException(ex);
        }
    }

    private Mono<ServerResponse> recoverSecretHandler(ServerRequest request) {

        Flux<SecretShareDTO> sharesFlux = request.bodyToFlux(SecretShareDTO.class);

        Mono<String> recoveredSecretMono;
        try {
            recoveredSecretMono = secretSharing.recoverSecret(sharesFlux);
            return recoveredSecretMono
                    .flatMap(recoveredSecret -> ServerResponse.ok()
                            .contentType(MediaType.TEXT_PLAIN)
                            .bodyValue(recoveredSecret))
                    .onErrorResume(this::handleException);

        } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException | SecurityException
                | IllegalArgumentException e) {
            return handleException(e);
        }
    }

    private Mono<ServerResponse> handleException(Throwable ex) {

        log.log(Level.SEVERE, ex.getMessage());
        HttpStatus status = HttpStatus.INTERNAL_SERVER_ERROR;

        if (ex instanceof InvalidKeyException
                || ex instanceof NoSuchAlgorithmException
                || ex instanceof SignatureException
                || ex instanceof SecurityException
                || ex instanceof IllegalArgumentException) {
            status = HttpStatus.INTERNAL_SERVER_ERROR;
        } else if (ex instanceof IllegalArgumentException) {
            status = HttpStatus.BAD_REQUEST;
        } else if (ex instanceof NoSuchElementException) {
            status = HttpStatus.NOT_FOUND;
        }

        return ServerResponse.status(status)
                .contentType(MediaType.TEXT_PLAIN)
                .bodyValue(ex.getMessage());
    }
}
