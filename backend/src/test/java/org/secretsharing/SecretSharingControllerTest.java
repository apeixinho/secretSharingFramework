package org.secretsharing;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.secretsharing.config.SerializerConfiguration;
import org.secretsharing.model.SecretShareDTO;
import org.secretsharing.service.SecretSharing;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.List;
import java.util.stream.Stream;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@WebFluxTest
@Import(SerializerConfiguration.class)
public class SecretSharingControllerTest {

    @MockBean
    private SecretSharing secretSharing;

    @Autowired
    private WebTestClient webTestClient;

    @Test
    public void testSecretSharingControllerDependency() {
        Assertions.assertNotNull(secretSharing);
    }


    @Test
    void testGetSecretShares() {

        // success case
        Flux<SecretShareDTO> mockedShareList = Flux.just(
                new SecretShareDTO(1, BigInteger.valueOf(12345), new byte[] { 0x01, 0x02, 0x03 }),
                new SecretShareDTO(2, BigInteger.valueOf(12345), new byte[] { 0x01, 0x02, 0x03 }),
                new SecretShareDTO(3, BigInteger.valueOf(12345), new byte[] { 0x01, 0x02, 0x03 }),
                new SecretShareDTO(4, BigInteger.valueOf(12345), new byte[] { 0x01, 0x02, 0x03 }));

        when(secretSharing.getSecretShares()).thenReturn(mockedShareList);

        webTestClient.get()
                .uri("/api/v1/secretShares")
                .exchange()
                .expectStatus().isOk()
                .expectBodyList(SecretShareDTO.class)
                .hasSize(4)
                .consumeWith(result -> {
                    List<SecretShareDTO> response = result.getResponseBody();
                    Assertions.assertNotNull(response);
                    Assertions.assertEquals(response.size(), 4);
                });

        // Exception case
        when(secretSharing.getSecretShares())
                .thenReturn(Flux.error(new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR)));

        webTestClient.get()
                .uri("/api/v1/secretShares")
                .exchange()
                .expectStatus().is5xxServerError()
                .returnResult(Flux.class)
                .getResponseBody()
                .as(StepVerifier::create)
                .expectError()
                .verify();

    }



    @Test
    public void testSplitSecret() throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        
        int k = 2;
        int n = 4;
        String secret = "Super Secret";

        // Create a mocked Flux of shares
        Flux<SecretShareDTO> mockedShareList = Flux.just(
                new SecretShareDTO(1, BigInteger.valueOf(12345), new byte[] { 0x01, 0x02, 0x03 }),
                new SecretShareDTO(2, BigInteger.valueOf(12345), new byte[] { 0x01, 0x02, 0x03 }),
                new SecretShareDTO(3, BigInteger.valueOf(12345), new byte[] { 0x01, 0x02, 0x03 }),
                new SecretShareDTO(4, BigInteger.valueOf(12345), new byte[] { 0x01, 0x02, 0x03 }));

        // Mock the behavior of the secretSharing.splitSecret() method
        when(secretSharing.splitSecret(anyInt(), anyInt(), anyString()))
                .thenReturn(mockedShareList);

        // Perform the request and assert the response
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
                    Assertions.assertEquals(response.size(), 4);
                });

        // Verify that the method was called with correct parameters
        verify(secretSharing, times(1)).splitSecret(eq(k), eq(n), eq(secret));
    }

    @Test
    public void testRecoverSecret() throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {

        Flux<SecretShareDTO> sharesToRecover = Flux.just(
                new SecretShareDTO(1, BigInteger.valueOf(12345), new byte[] { 0x01, 0x02, 0x03 }),
                new SecretShareDTO(2, BigInteger.valueOf(54321), new byte[] { 0x04, 0x05, 0x06 }));

        // Mock the behavior of the secretSharing.recoverSecret() method
        Mono<String> recoveredSecret = Mono.just("Recovered Secret");
        when(secretSharing.recoverSecret(any())).thenReturn(recoveredSecret);

        // Perform the request and assert the response
        webTestClient.post()
                .uri("/api/v1/recoverSecret")
                .contentType(MediaType.APPLICATION_JSON)
                .body(sharesToRecover, SecretShareDTO.class)
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class)
                .isEqualTo("Recovered Secret");

        // Verify that the method was called
        verify(secretSharing, times(1)).recoverSecret(any(Flux.class));
    }

    @ParameterizedTest
    @MethodSource("invalidParameters")
    public void splitSecret_Invalid_Parameters(int k, int n, String secret)
            throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, IllegalArgumentException {

        // Perform the request and assert the response
        webTestClient.get()
                .uri("/api/v1/splitSecret?k={k}&n={n}&secret={secret}", k, n, secret)
                .accept(MediaType.APPLICATION_JSON)
                .exchange()
                .expectStatus()
                .is5xxServerError();

        // Verify that the method was called with invalid parameters
        verify(secretSharing, times(1)).splitSecret(anyInt(), anyInt(), anyString());
    }

    @Test
    public void testRecoverSecret_Invalid_Parameters() throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {

        Flux<SecretShareDTO> invalidShares = Flux.just(
                new SecretShareDTO(-1, BigInteger.ZERO, null),
                new SecretShareDTO(-2, BigInteger.ZERO, null));

        // Perform the request and assert the response
        webTestClient.post()
                .uri("/api/v1/recoverSecret")
                .contentType(MediaType.APPLICATION_JSON)
                .body(invalidShares, SecretShareDTO.class)
                .exchange()
                .expectStatus()
                .is5xxServerError();

        // Verify that the method was called
        verify(secretSharing, times(1)).recoverSecret(any(Flux.class));
    }

    private static Stream<Arguments> invalidParameters() {
        return Stream.of(
                Arguments.of(0, 0, "Super Secret"),
                Arguments.of(0, 1, "Super Secret"),
                Arguments.of(1, 0, "Super Secret"),
                Arguments.of(4, 3, "Super Secret"),
                Arguments.of(2, 4, ""),
                Arguments.of(2, 4, "\n\t\t\n   \n\t"),
                Arguments.of(2, 4, null),
                Arguments.of(2, 61, "Super Secret"));
    }

}
