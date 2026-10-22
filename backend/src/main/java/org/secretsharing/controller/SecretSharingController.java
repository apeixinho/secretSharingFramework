package org.secretsharing.controller;

import java.util.List;

import org.secretsharing.model.SecretShareDTO;
import org.secretsharing.service.SecretSharing;
import org.springframework.http.HttpStatus;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
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

@RestController
@RequestMapping(SecretSharingController.BASE_URL)
@Validated
public class SecretSharingController {

	public static final String BASE_URL = "/api/v1";

	private final SecretSharing secretSharing;

	public SecretSharingController(SecretSharing secretSharing) {
		this.secretSharing = secretSharing;
	}

	@RequestMapping(value = "/splitSecret", method = RequestMethod.GET)
	@ResponseStatus(HttpStatus.OK)
	public List<SecretShareDTO> splitSecret(
			@RequestParam("k") @Min(1) @Max(60) int k,
			@RequestParam("n") @Min(1) @Max(60) int n,
			@RequestParam("secret") @NotBlank @Size(min = 1, max = 4096) String secret)
			throws Exception {
		return secretSharing.splitSecret(k, n, secret);
	}

	@PostMapping("/recoverSecret")
	@ResponseStatus(HttpStatus.OK)
	public String recoverSecret(@RequestBody @Validated List<SecretShareDTO> shares) throws Exception {
		return secretSharing.recoverSecret(shares);
	}
}
