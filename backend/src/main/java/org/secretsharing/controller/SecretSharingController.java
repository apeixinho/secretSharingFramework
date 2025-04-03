package org.secretsharing.controller;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.List;

import org.secretsharing.model.SecretShareDTO;
import org.secretsharing.service.SecretSharing;
import org.springframework.http.HttpStatus;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

@CrossOrigin(origins = "*")
@RestController
@RequestMapping(SecretSharingController.BASE_URL)
public class SecretSharingController {

    public static final String BASE_URL = "/api/v1";

    private final SecretSharing secretSharing;

    public SecretSharingController(SecretSharing secretSharing) {
        this.secretSharing = secretSharing;
    }

    @RequestMapping(value = "/splitSecret", method = RequestMethod.GET)
    @ResponseStatus(HttpStatus.OK)
    public List<SecretShareDTO> splitSecret(
            @Validated @RequestParam("k") @NotBlank @Min(value = 0) @Max(value = 300) int k,
            @RequestParam("n") @NotBlank @Min(value = 0) @Max(value = 300) int n,
            @RequestParam("secret") @NotBlank @Size(min = 3, max = 300) String secret)
            throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {

        return secretSharing.splitSecret(k, n, secret);

    }

    @RequestMapping(value = "/recoverSecret", method = RequestMethod.POST)
    @ResponseStatus(HttpStatus.OK)
    public String recoverSecret(
            @RequestBody @Validated List<SecretShareDTO> shares)
            throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {

        return secretSharing.recoverSecret(shares);

    }
}