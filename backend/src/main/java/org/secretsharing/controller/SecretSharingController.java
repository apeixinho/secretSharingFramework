package org.secretsharing.controller;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import org.secretsharing.model.SecretShareDTO;
import org.secretsharing.service.SecretSharing;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping(SecretSharingController.BASE_URL)
@Validated
public class SecretSharingController {

	public static final String BASE_URL = "/api/v1";

	private final SecretSharing secretSharing;

	public SecretSharingController(SecretSharing secretSharing) {
		this.secretSharing = secretSharing;
	}

	@GetMapping("/secretShares")
	@ResponseStatus(HttpStatus.OK)
	@Operation(summary = "List the last issued share set (in-memory)", responses = {
			@ApiResponse(responseCode = "200", description = "Shares",
					content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
							array = @ArraySchema(schema = @Schema(implementation = SecretShareDTO.class))))
	})
	public Flux<SecretShareDTO> secretShares() {
		return secretSharing.getSecretShares();
	}

	@GetMapping("/splitSecret")
	@ResponseStatus(HttpStatus.OK)
	@Operation(summary = "Split a secret into n signed shares", responses = {
			@ApiResponse(responseCode = "200", description = "Signed shares",
					content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
							array = @ArraySchema(schema = @Schema(implementation = SecretShareDTO.class)))),
			@ApiResponse(responseCode = "400", description = "Invalid parameters",
					content = @Content(mediaType = MediaType.TEXT_PLAIN_VALUE)),
			@ApiResponse(responseCode = "500", description = "Unexpected server error",
					content = @Content(mediaType = MediaType.TEXT_PLAIN_VALUE))
	})
	public Flux<SecretShareDTO> splitSecret(
			@RequestParam("k") @Min(1) @Max(60) int k,
			@RequestParam("n") @Min(1) @Max(60) int n,
			@RequestParam("secret") @NotBlank @Size(min = 1, max = 300) String secret) throws Exception {
		if (k > n) {
			return Flux.error(new IllegalArgumentException("Invalid parameter(s) provided."));
		}
		return secretSharing.splitSecret(k, n, secret);
	}

	@PostMapping("/recoverSecret")
	@ResponseStatus(HttpStatus.OK)
	@Operation(summary = "Recover a secret from signed shares", responses = {
			@ApiResponse(responseCode = "200", description = "Recovered secret",
					content = @Content(mediaType = MediaType.TEXT_PLAIN_VALUE)),
			@ApiResponse(responseCode = "400", description = "Invalid share payload",
					content = @Content(mediaType = MediaType.TEXT_PLAIN_VALUE)),
			@ApiResponse(responseCode = "403", description = "Signature verification failed",
					content = @Content(mediaType = MediaType.TEXT_PLAIN_VALUE)),
			@ApiResponse(responseCode = "429", description = "Rate limit exceeded",
					content = @Content(mediaType = MediaType.TEXT_PLAIN_VALUE)),
			@ApiResponse(responseCode = "500", description = "Unexpected server error",
					content = @Content(mediaType = MediaType.TEXT_PLAIN_VALUE))
	})
	public Mono<String> recoverSecret(@RequestBody Flux<SecretShareDTO> shares) throws Exception {
		return secretSharing.recoverSecret(shares);
	}
}
