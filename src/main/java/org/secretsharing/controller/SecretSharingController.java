package org.secretsharing.controller;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.secretsharing.model.SecretShareDTO;
import org.secretsharing.service.SecretSharing;
import org.springframework.http.HttpStatus;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
//import lombok.extern.java.Log;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

// @Log
@CrossOrigin(origins = "*")
@RestController
@RequestMapping(SecretSharingController.BASE_URL)
public class SecretSharingController {

    public static final String BASE_URL = "/api/v1";

    private final SecretSharing secretSharing;

    public SecretSharingController(SecretSharing secretSharing) {
        this.secretSharing = secretSharing;
    }

    @GetMapping(value = "/splitSecret")
    @ResponseStatus(HttpStatus.OK)
    public Flux<SecretShareDTO> splitSecret(
            @Validated @RequestParam("k") @NotBlank @Min(value = 0) @Max(value = 300) int k,
            @RequestParam("n") @NotBlank @Min(value = 0) @Max(value = 300) int n,
            @RequestParam("secret") @NotBlank @Size(min = 3, max = 300) String secret)
            throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, IllegalArgumentException {

        return secretSharing.splitSecret(k, n, secret)
                .onErrorResume(e -> {
                    // log.log(Level.SEVERE, e.getMessage());
                    return Flux.error(e);
                });
    }

    @PostMapping(value = "/recoverSecret")
    @ResponseStatus(HttpStatus.OK)
    public Mono<String> recoverSecret(
            @RequestBody @Validated Flux<SecretShareDTO> shares)
            throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, SecurityException,
            IllegalArgumentException {

        return secretSharing.recoverSecret(shares)
                .onErrorResume(e -> {
                    // log.log(Level.SEVERE, e.getMessage());
                    return Mono.error(e);
                });
    }

}
