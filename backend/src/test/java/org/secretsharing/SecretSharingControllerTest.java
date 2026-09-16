package org.secretsharing;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.secretsharing.config.SerializerConfiguration;
import org.secretsharing.controller.SecretSharingController;
import org.secretsharing.model.SecretShareDTO;
import org.secretsharing.model.SplitSecretRequest;
import org.secretsharing.service.SecretSharing;
import org.secretsharing.web.GlobalExceptionHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.math.BigInteger;
import java.util.List;
import java.util.stream.Stream;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@WebFluxTest(controllers = SecretSharingController.class)
@Import({ SerializerConfiguration.class, GlobalExceptionHandler.class })
class SecretSharingControllerTest {

    @MockitoBean
    private SecretSharing secretSharing;

    @Autowired
    private WebTestClient webTestClient;

    @Test
    void testSplitSecret() {
        int k = 2;
        int n = 4;
        String secret = "Super Secret";

        Flux<SecretShareDTO> mockedShareList = Flux.just(
                new SecretShareDTO(1, BigInteger.valueOf(12345), new byte[] { 0x01, 0x02, 0x03 }),
                new SecretShareDTO(2, BigInteger.valueOf(12345), new byte[] { 0x01, 0x02, 0x03 }),
                new SecretShareDTO(3, BigInteger.valueOf(12345), new byte[] { 0x01, 0x02, 0x03 }),
                new SecretShareDTO(4, BigInteger.valueOf(12345), new byte[] { 0x01, 0x02, 0x03 }));

        when(secretSharing.splitSecret(any(SplitSecretRequest.class))).thenReturn(mockedShareList);

        webTestClient.post()
                .uri("/api/v1/splitSecret")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(new SplitSecretRequest(k, n, secret))
                .exchange()
                .expectStatus().isOk()
                .expectBodyList(SecretShareDTO.class)
                .hasSize(4)
                .consumeWith(result -> {
                    List<SecretShareDTO> response = result.getResponseBody();
                    Assertions.assertNotNull(response);
                    Assertions.assertEquals(4, response.size());
                });

        verify(secretSharing, times(1)).splitSecret(any(SplitSecretRequest.class));
    }

    @Test
    void testRecoverSecret() {
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

        verify(secretSharing, times(1)).recoverSecret(any());
    }

    @ParameterizedTest
    @MethodSource("invalidBodies")
    void splitSecret_Invalid_Parameters(SplitSecretRequest request) {
        webTestClient.post()
                .uri("/api/v1/splitSecret")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(request)
                .exchange()
                .expectStatus()
                .isBadRequest();
    }

    @Test
    void splitSecret_ServiceIllegalArgument_IsBadRequest() {
        when(secretSharing.splitSecret(any(SplitSecretRequest.class)))
                .thenReturn(Flux.error(new IllegalArgumentException("Invalid parameter(s) provided.")));

        webTestClient.post()
                .uri("/api/v1/splitSecret")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(new SplitSecretRequest(2, 4, "Super Secret"))
                .exchange()
                .expectStatus()
                .isBadRequest()
                .expectBody()
                .jsonPath("$.error").isEqualTo("Invalid parameter(s) provided.");
    }

    @Test
    void recoverSecret_InvalidSignature_IsForbidden() {
        when(secretSharing.recoverSecret(any()))
                .thenReturn(Mono.error(new SecurityException("Invalid signature for share at index: 1")));

        webTestClient.post()
                .uri("/api/v1/recoverSecret")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("""
                        [{"index":1,"share":"123","signature":"AQID"}]
                        """)
                .exchange()
                .expectStatus()
                .isForbidden();
    }

    private static Stream<Arguments> invalidBodies() {
        return Stream.of(
                Arguments.of(new SplitSecretRequest(0, 1, "Super Secret")),
                Arguments.of(new SplitSecretRequest(1, 0, "Super Secret")),
                Arguments.of(new SplitSecretRequest(2, 4, "")),
                Arguments.of(new SplitSecretRequest(2, 4, "ab")),
                Arguments.of(new SplitSecretRequest(2, 61, "Super Secret")));
    }
}
