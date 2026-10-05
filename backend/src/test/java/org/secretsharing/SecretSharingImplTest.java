package org.secretsharing;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.secretsharing.model.SecretShareDTO;
import org.secretsharing.model.SplitSecretRequest;
import org.secretsharing.service.SecretSharing;
import org.secretsharing.service.SecretSharingImpl;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.stream.IntStream;
import java.util.stream.Stream;

class SecretSharingImplTest {

    private static final String HASH_ALGORITHM = "SHA256withRSA";

    private SecretSharing secretSharing;
    private Flux<SecretShareDTO> shares;

    private final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
    private final KeyPair keyPair;
    private final SecureRandom random = new SecureRandom();

    private int bitSize = 512;
    private int maxByteSize = (bitSize - 1) / 8;
    private BigInteger prime = BigInteger.probablePrime(bitSize, random);
    private final int maxShares = 60;

    SecretSharingImplTest() throws NoSuchAlgorithmException {
        keyPairGenerator.initialize(512);
        keyPair = keyPairGenerator.generateKeyPair();
    }

    @BeforeEach
    void setupInit() {
        secretSharing = new SecretSharingImpl(maxShares, prime, random, bitSize, maxByteSize, keyPair, HASH_ALGORITHM);
        shares = Flux.empty();
    }

    @Test
    void splitSecret_NullOrEmptySecret() {
        StepVerifier.create(secretSharing.splitSecret(new SplitSecretRequest(4, 9, null)))
                .expectError(IllegalArgumentException.class)
                .verify();

        StepVerifier.create(secretSharing.splitSecret(new SplitSecretRequest(4, 9, "")))
                .expectError(IllegalArgumentException.class)
                .verify();

        StepVerifier.create(secretSharing.splitSecret(new SplitSecretRequest(4, 9, "\n\t\t\n   \n\t  ")))
                .expectError(IllegalArgumentException.class)
                .verify();
    }

    @ParameterizedTest
    @MethodSource("invalidParameters")
    void splitSecret_Invalid_Parameters(int k, int n, String secret) {
        StepVerifier.create(secretSharing.splitSecret(new SplitSecretRequest(k, n, secret)))
                .expectErrorSatisfies(throwable -> {
                    Assertions.assertInstanceOf(IllegalArgumentException.class, throwable);
                    Assertions.assertEquals("Invalid parameter(s) provided.", throwable.getMessage());
                }).verify();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "Hello\uD800World!",
            "This is a test\uDC00"
    })
    void splitSecret_InvalidUnicodeCharactersInSecret(String secret) {
        StepVerifier.create(secretSharing.splitSecret(new SplitSecretRequest(3, 7, secret)))
                .expectErrorSatisfies(throwable -> {
                    Assertions.assertInstanceOf(IllegalArgumentException.class, throwable);
                    Assertions.assertEquals("Invalid character(s) in secret.", throwable.getMessage());
                })
                .verify();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            """
                    As armas e os barões assinalados
                    Que da ocidental praia Lusitana,
                    Por mares nunca de antes navegados,
                    Passaram ainda além da Taprobana,
                    Em perigos e guerras esforçados,
                    Mais do que prometia a força humana,
                    E entre gente remota edificaram
                    Novo Reino, que tanto sublimaram;""",
            """
                    1. Simplicity is a great virtue but it requires hard work to achieve it and education to appreciate it.
                    2. If debugging is the process of removing software bugs, then programming is the process of putting them in.
                    3. Computer science is no more about computers than astronomy is about telescopes.
                    4. The computing scientist's main challenge is not to get confused by the complexities of his own making.
                    5. Elegance is not a dispensable luxury but a quality that decides between success and failure."""
    })
    void splitSecret_SecretOverflow(String secret) {
        StepVerifier.create(secretSharing.splitSecret(new SplitSecretRequest(3, 7, secret)))
                .expectErrorSatisfies(throwable -> {
                    Assertions.assertInstanceOf(IllegalArgumentException.class, throwable);
                    Assertions.assertEquals("Secret byte size overflow for current bit size.",
                            throwable.getMessage());
                })
                .verify();
    }

    @Test
    void splitSecret_NeverEmitsIndexZero() {
        StepVerifier.create(secretSharing.splitSecret(new SplitSecretRequest(2, 4, "no-zero-share")))
                .assertNext(share -> Assertions.assertEquals(1, share.getIndex()))
                .assertNext(share -> Assertions.assertEquals(2, share.getIndex()))
                .assertNext(share -> Assertions.assertEquals(3, share.getIndex()))
                .assertNext(share -> Assertions.assertEquals(4, share.getIndex()))
                .verifyComplete();
    }

    @ParameterizedTest
    @MethodSource("validKAndNValues")
    void splitSecretAndRecover_Valid_K_N_Parameters(int k, int n) {
        String secret = "For your eyes only...\n\nSuper Top Secret\n42";
        shares = secretSharing.splitSecret(new SplitSecretRequest(k, n, secret));
        StepVerifier.create(shares).expectNextCount(n).expectComplete().verify();

        Flux<SecretShareDTO> selectedShares = getSubsetShares(shares, getRandomIndexes(k, n));
        StepVerifier.create(selectedShares).expectNextCount(k).expectComplete().verify();

        Mono<String> recoveredSecret = secretSharing.recoverSecret(selectedShares);
        StepVerifier.create(recoveredSecret).expectNext(secret).expectComplete().verify();
    }

    @ParameterizedTest
    @MethodSource("validKAndNLargeValues")
    void splitSecretAndRecover_Valid_K_N_LargeParameters(int k, int n) {
        bitSize = 256;
        maxByteSize = (bitSize - 1) / 8;
        prime = BigInteger.probablePrime(bitSize, random);
        secretSharing = new SecretSharingImpl(maxShares, prime, random, bitSize, maxByteSize, keyPair, HASH_ALGORITHM);

        String secret = "Little Secret...\n\n42";
        shares = secretSharing.splitSecret(new SplitSecretRequest(k, n, secret));
        StepVerifier.create(shares).expectNextCount(n).expectComplete().verify();

        Flux<SecretShareDTO> selectedShares = getSubsetShares(shares, getRandomIndexes(k, n));
        StepVerifier.create(selectedShares).expectNextCount(k).expectComplete().verify();

        Mono<String> recoveredSecret = secretSharing.recoverSecret(selectedShares);
        StepVerifier.create(recoveredSecret).expectNext(secret).expectComplete().verify();
    }

    @Test
    void splitSecretAndRecover_UnicodeCharactersSecret() {
        int k = 2;
        int n = 4;
        String secret = "Unicode characters: \u00A9 \u00AE \u260E \u2764";

        shares = secretSharing.splitSecret(new SplitSecretRequest(k, n, secret));
        StepVerifier.create(shares).expectNextCount(n).expectComplete().verify();

        Flux<SecretShareDTO> selectedShares = getSubsetShares(shares, getRandomIndexes(k, n));
        StepVerifier.create(selectedShares).expectNextCount(k).expectComplete().verify();

        Mono<String> recoveredSecret = secretSharing.recoverSecret(selectedShares);
        StepVerifier.create(recoveredSecret).expectNext(secret).expectComplete().verify();
    }

    @Test
    void splitSecretAndRecover_MultilineSecret() {
        bitSize = 1024;
        maxByteSize = (bitSize - 1) / 8;
        prime = BigInteger.probablePrime(bitSize, random);
        secretSharing = new SecretSharingImpl(maxShares, prime, random, bitSize, maxByteSize, keyPair, HASH_ALGORITHM);

        int k = 3;
        int n = 6;
        String secret = """
                This is a  simple secret message.
                This is a new line
                Some more lines...


                And more
                \tMore
                \t\tAlways more""";

        shares = secretSharing.splitSecret(new SplitSecretRequest(k, n, secret));
        StepVerifier.create(shares).expectNextCount(n).expectComplete().verify();

        Flux<SecretShareDTO> selectedShares = getSubsetShares(shares, getRandomIndexes(k, n));
        StepVerifier.create(selectedShares).expectNextCount(k).expectComplete().verify();

        Mono<String> recoveredSecret = secretSharing.recoverSecret(selectedShares);
        StepVerifier.create(recoveredSecret).expectNext(secret).expectComplete().verify();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "As armas e os barões assinalados",
            "Que da ocidental praia Lusitana,",
            "Por mares nunca de antes navegados,",
            "For your eyes only.\n\n\tSuper Top Secret\n\n\t\tTop Secret\n\n\t\t42"
    })
    void splitSecretAndRecover_SmallSecretAndCustomBitSize(String secret) {
        bitSize = 768;
        maxByteSize = (bitSize - 1) / 8;
        prime = BigInteger.probablePrime(bitSize, random);
        secretSharing = new SecretSharingImpl(maxShares, prime, random, bitSize, maxByteSize, keyPair, HASH_ALGORITHM);

        int k = 3;
        int n = 6;

        shares = secretSharing.splitSecret(new SplitSecretRequest(k, n, secret));
        StepVerifier.create(shares).expectNextCount(n).expectComplete().verify();

        Flux<SecretShareDTO> selectedShares = getSubsetShares(shares, getRandomIndexes(k, n));
        StepVerifier.create(selectedShares).expectNextCount(k).expectComplete().verify();

        Mono<String> recoveredSecret = secretSharing.recoverSecret(selectedShares);
        StepVerifier.create(recoveredSecret).expectNext(secret).expectComplete().verify();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            """
                    As armas e os barões assinalados
                    Que da ocidental praia Lusitana,
                    Por mares nunca de antes navegados,
                    Passaram ainda além da Taprobana,
                    Em perigos e guerras esforçados,
                    Mais do que prometia a força humana,
                    E entre gente remota edificaram
                    Novo Reino, que tanto sublimaram;""",
            """
                    1. Simplicity is a great virtue but it requires hard work to achieve it and education to appreciate it.
                    2. If debugging is the process of removing software bugs, then programming is the process of putting them in.
                    3. Computer science is no more about computers than astronomy is about telescopes.
                    4. The computing scientist's main challenge is not to get confused by the complexities of his own making.
                    5. Elegance is not a dispensable luxury but a quality that decides between success and failure."""
    })
    void splitSecretAndRecover_LargeSecretAndCustomBitSize(String secret) {
        bitSize = 4096;
        maxByteSize = (bitSize - 1) / 8;
        prime = BigInteger.probablePrime(bitSize, random);
        secretSharing = new SecretSharingImpl(maxShares, prime, random, bitSize, maxByteSize, keyPair, HASH_ALGORITHM);

        int k = 2;
        int n = 4;

        shares = secretSharing.splitSecret(new SplitSecretRequest(k, n, secret));
        StepVerifier.create(shares).expectNextCount(n).expectComplete().verify();

        Flux<SecretShareDTO> selectedShares = getSubsetShares(shares, getRandomIndexes(k, n));
        StepVerifier.create(selectedShares).expectNextCount(k).expectComplete().verify();

        Mono<String> recoveredSecret = secretSharing.recoverSecret(selectedShares);
        StepVerifier.create(recoveredSecret).expectNext(secret).expectComplete().verify();
    }

    private static Stream<Arguments> validKAndNValues() {
        return Stream.of(
                Arguments.of(1, 1),
                Arguments.of(1, 2),
                Arguments.of(2, 2),
                Arguments.of(3, 6),
                Arguments.of(10, 10));
    }

    private static Stream<Arguments> validKAndNLargeValues() {
        return Stream.of(
                Arguments.of(12, 20),
                Arguments.of(24, 32),
                Arguments.of(32, 48),
                Arguments.of(48, 60),
                Arguments.of(60, 60));
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
                Arguments.of(2, 301, "Super Secret"));
    }

    private int[] getRandomIndexes(int k, int n) {
        // Indexes are now 1..n
        return random.ints(1, n + 1).distinct().limit(k).toArray();
    }

    private Flux<SecretShareDTO> getSubsetShares(Flux<SecretShareDTO> shareFlux, int[] indexes) {
        return shareFlux.filter(share -> IntStream.of(indexes).anyMatch(i -> i == share.getIndex()));
    }
}
