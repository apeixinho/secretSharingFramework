package org.secretsharing.controller;

import jakarta.validation.Valid;
import org.secretsharing.model.SecretShareDTO;
import org.secretsharing.model.SplitSecretRequest;
import org.secretsharing.service.SecretSharing;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Validated
@RestController
@RequestMapping(SecretSharingController.BASE_URL)
@Tag(name = "Secret Sharing", description = "Shamir secret split and recovery")
public class SecretSharingController {

    public static final String BASE_URL = "/api/v1";

    private final SecretSharing secretSharing;

    public SecretSharingController(SecretSharing secretSharing) {
        this.secretSharing = secretSharing;
    }

    @PostMapping(value = "/splitSecret", consumes = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.OK)
    @Operation(summary = "Split a secret into signed shares",
            description = "Returns n shares with indexes 1..n. Any k of them can reconstruct the secret.")
    public Flux<SecretShareDTO> splitSecret(@Valid @RequestBody SplitSecretRequest request) {
        return secretSharing.splitSecret(request);
    }

    @PostMapping(value = "/recoverSecret", consumes = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.OK)
    @Operation(summary = "Recover a secret from shares",
            description = "Verifies each share signature, then interpolates the secret. Requires at least k valid shares.")
    public Mono<String> recoverSecret(@RequestBody Flux<SecretShareDTO> shares) {
        return secretSharing.recoverSecret(shares);
    }
}
