package org.secretsharing.config;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.secretsharing.model.SecretShareDTO;
import org.secretsharing.service.SecretSharing;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.reactive.function.server.RequestPredicates;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.parameters.RequestBody;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import org.springdoc.core.annotations.RouterOperation;
import org.springdoc.core.annotations.RouterOperations;

@Configuration
public class RouterConfiguration {

	private static final Logger log = Logger.getLogger(RouterConfiguration.class.getName());

	private static final String MSG_BAD_REQUEST = "Invalid request parameters.";
	private static final String MSG_MISSING_QUERY = "Missing or invalid query parameters. Required: k, n, secret.";
	private static final String MSG_FORBIDDEN = "Share signature verification failed.";
	private static final String MSG_UNEXPECTED = "Unexpected error.";

	@Autowired
	private SecretSharing secretSharing;

	@Value("${secret-sharing.maxShares:60}")
	private int maxShares;

	@RouterOperations({
			@RouterOperation(
					path = "/api/v1/splitSecret",
					method = RequestMethod.GET,
					operation = @Operation(
							operationId = "splitSecret",
							summary = "Split a secret into n signed shares",
							description = "Requires threshold k of n shares to recover. Constraints: 1 <= k <= n <= maxShares.",
							parameters = {
									@Parameter(name = "k", in = ParameterIn.QUERY, required = true,
											description = "Threshold (minimum shares needed to recover)"),
									@Parameter(name = "n", in = ParameterIn.QUERY, required = true,
											description = "Total number of shares to issue"),
									@Parameter(name = "secret", in = ParameterIn.QUERY, required = true,
											description = "UTF-8 secret to split (sent as a query param on this branch)")
							},
							responses = {
									@ApiResponse(responseCode = "200", description = "Signed shares",
											content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
													array = @ArraySchema(schema = @Schema(implementation = SecretShareDTO.class)))),
									@ApiResponse(responseCode = "400", description = "Invalid or missing parameters",
											content = @Content(mediaType = MediaType.TEXT_PLAIN_VALUE)),
									@ApiResponse(responseCode = "500", description = "Unexpected server error",
											content = @Content(mediaType = MediaType.TEXT_PLAIN_VALUE))
							})),
			@RouterOperation(
					path = "/api/v1/recoverSecret",
					method = RequestMethod.POST,
					operation = @Operation(
							operationId = "recoverSecret",
							summary = "Recover a secret from signed shares",
							requestBody = @RequestBody(required = true, content = @Content(
									mediaType = MediaType.APPLICATION_JSON_VALUE,
									array = @ArraySchema(schema = @Schema(implementation = SecretShareDTO.class)))),
							responses = {
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
							}))
	})
	@Bean
	RouterFunction<ServerResponse> secretSharingRoutes() {
		return RouterFunctions.route()
				.GET("/api/v1/splitSecret",
						RequestPredicates.all().and(RequestPredicates.method(HttpMethod.GET)),
						this::splitSecretHandler)
				.POST("/api/v1/recoverSecret",
						RequestPredicates.all().and(RequestPredicates.method(HttpMethod.POST)),
						this::recoverSecretHandler)
				.build();
	}

	private Mono<ServerResponse> splitSecretHandler(ServerRequest request) {
		final int k;
		final int n;
		final String secret;
		try {
			k = Integer.parseInt(request.queryParam("k").orElseThrow());
			n = Integer.parseInt(request.queryParam("n").orElseThrow());
			secret = request.queryParam("secret").orElseThrow();
		} catch (Exception ex) {
			return badRequest(MSG_MISSING_QUERY);
		}

		if (!isValidSplitParams(k, n, secret)) {
			return badRequest(MSG_BAD_REQUEST);
		}

		try {
			Flux<SecretShareDTO> sharesFlux = secretSharing.splitSecret(k, n, secret);
			return ServerResponse.ok()
					.contentType(MediaType.APPLICATION_JSON)
					.body(sharesFlux, SecretShareDTO.class)
					.onErrorResume(this::handleException);
		} catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException | IllegalArgumentException ex) {
			return handleException(ex);
		}
	}

	private Mono<ServerResponse> recoverSecretHandler(ServerRequest request) {
		Flux<SecretShareDTO> sharesFlux = request.bodyToFlux(SecretShareDTO.class);
		try {
			return secretSharing.recoverSecret(sharesFlux)
					.flatMap(recoveredSecret -> ServerResponse.ok()
							.contentType(MediaType.TEXT_PLAIN)
							.bodyValue(recoveredSecret))
					.onErrorResume(this::handleException);
		} catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException | SecurityException
				| IllegalArgumentException e) {
			return handleException(e);
		}
	}

	private boolean isValidSplitParams(int k, int n, String secret) {
		return k >= 1
				&& n >= 1
				&& k <= n
				&& n <= maxShares
				&& secret != null
				&& !secret.strip().isBlank();
	}

	private Mono<ServerResponse> handleException(Throwable ex) {
		// Never log exception messages — they may include secret or share material.
		log.log(Level.WARNING, "Request failed: {0}", ex.getClass().getSimpleName());

		if (ex instanceof IllegalArgumentException) {
			return badRequest(MSG_BAD_REQUEST);
		}
		if (ex instanceof SecurityException) {
			return ServerResponse.status(HttpStatus.FORBIDDEN)
					.contentType(MediaType.TEXT_PLAIN)
					.bodyValue(MSG_FORBIDDEN);
		}
		if (ex instanceof InvalidKeyException
				|| ex instanceof NoSuchAlgorithmException
				|| ex instanceof SignatureException) {
			return ServerResponse.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.contentType(MediaType.TEXT_PLAIN)
					.bodyValue(MSG_UNEXPECTED);
		}
		return ServerResponse.status(HttpStatus.INTERNAL_SERVER_ERROR)
				.contentType(MediaType.TEXT_PLAIN)
				.bodyValue(MSG_UNEXPECTED);
	}

	private static Mono<ServerResponse> badRequest(String message) {
		return ServerResponse.badRequest()
				.contentType(MediaType.TEXT_PLAIN)
				.bodyValue(message);
	}
}
