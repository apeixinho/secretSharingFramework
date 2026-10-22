package org.secretsharing;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.secretsharing.config.RouterConfiguration;
import org.secretsharing.config.SerializerConfiguration;
import org.secretsharing.model.SecretShareDTO;
import org.secretsharing.service.SecretSharing;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.List;
import java.util.stream.Stream;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@WebFluxTest
@Import({ SerializerConfiguration.class, RouterConfiguration.class })
public class SecretSharingControllerTest {

	@MockitoBean
	private SecretSharing secretSharing;

	@Autowired
	private WebTestClient webTestClient;

	@Test
	public void testSecretSharingControllerDependency() {
		Assertions.assertNotNull(secretSharing);
	}

	@Test
	public void testSplitSecret() throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
		int k = 2;
		int n = 4;
		String secret = "Super Secret";

		Flux<SecretShareDTO> mockedShareList = Flux.just(
				new SecretShareDTO(1, BigInteger.valueOf(12345), new byte[] { 0x01, 0x02, 0x03 }),
				new SecretShareDTO(2, BigInteger.valueOf(12345), new byte[] { 0x01, 0x02, 0x03 }),
				new SecretShareDTO(3, BigInteger.valueOf(12345), new byte[] { 0x01, 0x02, 0x03 }),
				new SecretShareDTO(4, BigInteger.valueOf(12345), new byte[] { 0x01, 0x02, 0x03 }));

		when(secretSharing.splitSecret(anyInt(), anyInt(), anyString())).thenReturn(mockedShareList);

		webTestClient.get()
				.uri("/api/v1/splitSecret?k={k}&n={n}&secret={secret}", k, n, secret)
				.accept(MediaType.APPLICATION_JSON)
				.exchange()
				.expectStatus().isOk()
				.expectBodyList(SecretShareDTO.class)
				.hasSize(4)
				.consumeWith(result -> {
					List<SecretShareDTO> response = result.getResponseBody();
					Assertions.assertNotNull(response);
					Assertions.assertEquals(4, response.size());
				});

		verify(secretSharing, times(1)).splitSecret(eq(k), eq(n), eq(secret));
	}

	@Test
	public void testRecoverSecret() throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
		Flux<SecretShareDTO> sharesToRecover = Flux.just(
				new SecretShareDTO(1, BigInteger.valueOf(12345), new byte[] { 0x01, 0x02, 0x03 }),
				new SecretShareDTO(2, BigInteger.valueOf(54321), new byte[] { 0x04, 0x05, 0x06 }));

		when(secretSharing.recoverSecret(any())).thenReturn(Mono.just("Recovered Secret"));

		webTestClient.post()
				.uri("/api/v1/recoverSecret")
				.contentType(MediaType.APPLICATION_JSON)
				.body(sharesToRecover, SecretShareDTO.class)
				.exchange()
				.expectStatus().isOk()
				.expectBody(String.class)
				.isEqualTo("Recovered Secret");

		verify(secretSharing, times(1)).recoverSecret(any(Flux.class));
	}

	@ParameterizedTest
	@MethodSource("invalidParameters")
	public void splitSecret_Invalid_Parameters(int k, int n, String secret) throws Exception {
		webTestClient.get()
				.uri("/api/v1/splitSecret?k={k}&n={n}&secret={secret}", k, n, secret)
				.accept(MediaType.APPLICATION_JSON)
				.exchange()
				.expectStatus().isBadRequest()
				.expectBody(String.class)
				.isEqualTo("Invalid request parameters.");

		verify(secretSharing, never()).splitSecret(anyInt(), anyInt(), anyString());
	}

	@Test
	public void splitSecret_MissingQueryParams_ReturnsBadRequest() throws Exception {
		webTestClient.get()
				.uri("/api/v1/splitSecret?k=2&n=3")
				.accept(MediaType.APPLICATION_JSON)
				.exchange()
				.expectStatus().isBadRequest();

		verify(secretSharing, never()).splitSecret(anyInt(), anyInt(), anyString());
	}

	@Test
	public void testRecoverSecret_Invalid_Parameters() throws Exception {
		when(secretSharing.recoverSecret(any()))
				.thenReturn(Mono.error(new IllegalArgumentException("Empty shares provided.")));

		Flux<SecretShareDTO> invalidShares = Flux.just(
				new SecretShareDTO(-1, BigInteger.ZERO, new byte[] { 0x01 }),
				new SecretShareDTO(-2, BigInteger.ZERO, new byte[] { 0x02 }));

		webTestClient.post()
				.uri("/api/v1/recoverSecret")
				.contentType(MediaType.APPLICATION_JSON)
				.body(invalidShares, SecretShareDTO.class)
				.exchange()
				.expectStatus().isBadRequest()
				.expectBody(String.class)
				.isEqualTo("Invalid request parameters.");

		verify(secretSharing, times(1)).recoverSecret(any(Flux.class));
	}

	@Test
	public void testRecoverSecret_InvalidSignature_ReturnsForbidden() throws Exception {
		when(secretSharing.recoverSecret(any()))
				.thenReturn(Mono.error(new SecurityException("Invalid signature")));

		Flux<SecretShareDTO> shares = Flux.just(
				new SecretShareDTO(1, BigInteger.valueOf(1), new byte[] { 0x01 }));

		webTestClient.post()
				.uri("/api/v1/recoverSecret")
				.contentType(MediaType.APPLICATION_JSON)
				.body(shares, SecretShareDTO.class)
				.exchange()
				.expectStatus().isForbidden()
				.expectBody(String.class)
				.isEqualTo("Share signature verification failed.");
	}

	private static Stream<Arguments> invalidParameters() {
		return Stream.of(
				Arguments.of(0, 0, "Super Secret"),
				Arguments.of(0, 1, "Super Secret"),
				Arguments.of(1, 0, "Super Secret"),
				Arguments.of(4, 3, "Super Secret"),
				Arguments.of(2, 4, ""),
				Arguments.of(2, 4, "\n\t\t\n   \n\t"),
				Arguments.of(2, 61, "Super Secret"));
	}
}
