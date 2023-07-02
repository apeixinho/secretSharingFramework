package org.secretsharing;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.secretsharing.config.CryptographyConfiguration;
import org.secretsharing.model.SecretShareDTO;
import org.secretsharing.service.SecretSharing;
import org.secretsharing.service.SecretSharingImpl;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;

import java.util.stream.IntStream;
import java.util.stream.Stream;

import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.when;

public class SecretSharingImplTest {

    private SecretSharing secretSharing;

    private Flux<SecretShareDTO> shares;

    private final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");

    private final KeyPair keyPair = keyPairGenerator.generateKeyPair();

    private final Signature signature = Signature.getInstance("SHA256withRSA");

    private final SecureRandom random = new SecureRandom();

    private int bitSize = 512;

    private int maxByteSize = ((bitSize - 1) / 8);

    private BigInteger prime = BigInteger.probablePrime(bitSize, random);

    private final int maxShares = 60;

    @Mock
    private CryptographyConfiguration configuration;

    public SecretSharingImplTest() throws NoSuchAlgorithmException {
        keyPairGenerator.initialize(512);
    }

    @BeforeEach
    public void setupInit() throws NoSuchAlgorithmException {

        MockitoAnnotations.openMocks(this);

        when(configuration.secretSharingKeyPair()).thenReturn(keyPair);
        when(configuration.secretSharingSignature()).thenReturn(signature);

        when(configuration.secretSharingPrime(anyInt())).thenAnswer(invocation -> {
            int bitSizeArgument = invocation.getArgument(0);
            return BigInteger.probablePrime(bitSizeArgument, random);
        });

        when(configuration.secretSharingRandom()).thenReturn(random);
        when(configuration.bitSize()).thenReturn(bitSize);

        when(configuration.maxByteSize(anyInt())).thenAnswer(invocation -> {
            int bitSizeArgument = invocation.getArgument(0);
            return (bitSizeArgument - 1) / 8;
        });
        when(configuration.maxShares()).thenReturn(maxShares);

        secretSharing = new SecretSharingImpl(maxShares, prime, random, bitSize, maxByteSize, keyPair, signature);
        shares = Flux.empty();
    }

    @Test
    public void splitSecret_NullOrEmptySecret()
            throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, AssertionError {
        StepVerifier.create(secretSharing.splitSecret(4, 9, null))
                .expectError(IllegalArgumentException.class)
                .verify();

        StepVerifier.create(secretSharing.splitSecret(4, 9, ""))
                .expectError(IllegalArgumentException.class)
                .verify();

        StepVerifier.create(secretSharing.splitSecret(4, 9, "\n\t\t\n   \n\t  "))
                .expectError(IllegalArgumentException.class)
                .verify();
    }

    @ParameterizedTest
    @MethodSource("invalidParameters")
    public void splitSecret_Invalid_Parameters(int k, int n, String secret)
            throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, AssertionError {
        StepVerifier.create(secretSharing.splitSecret(k, n, secret))
                .expectErrorSatisfies(throwable -> {
                    Assertions.assertTrue(throwable instanceof IllegalArgumentException);
                    Assertions.assertEquals("Invalid parameter(s) provided.",
                            throwable.getMessage());
                }).verify();

    }

    @ParameterizedTest
    @ValueSource(strings = {
            "Hello\uD800World!",
            "This is a test\uDC00"
    })
    public void splitSecret_InvalidUnicodeCharactersInSecret(String secret)
            throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, AssertionError {

        StepVerifier.create(secretSharing.splitSecret(3, 7, secret))
                .expectErrorSatisfies(throwable -> {
                    Assertions.assertTrue(throwable instanceof IllegalArgumentException);
                    Assertions.assertEquals("Invalid character(s) in secret.",
                            throwable.getMessage());
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
                    2. If debugging is the process of removing software bugs, then programming must be the process of putting them in.
                    3. Computer science is no more about computers than astronomy is about telescopes.
                    4. The computing scientist's main challenge is not to get confused by the complexities of his own making.
                    5. Elegance is not a dispensable luxury but a quality that decides between success and failure."""
    })
    public void splitSecret_SecretOverflow(String secret)
            throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, AssertionError {

        StepVerifier.create(secretSharing.splitSecret(3, 7, secret))
                .expectErrorSatisfies(throwable -> {
                    Assertions.assertTrue(throwable instanceof IllegalArgumentException);
                    Assertions.assertEquals("Secret byte size overflow for current bit size.",
                            throwable.getMessage());
                })
                .verify();

    }

    @ParameterizedTest
    @MethodSource("validKAndNValues")
    public void splitSecretAndRecover_Valid_K_N_Parameters(int k, int n)
            throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {

        String secret = "For your eyes only...\n\nSuper Top Secret\n42";
        // Split the secret into shares
        shares = secretSharing.splitSecret(k, n, secret);
        // number of generated shares is correct
        StepVerifier.create(shares).expectNextCount(n).expectComplete().verify();
        // Select k shares for secret recovery
        Flux<SecretShareDTO> selectedShares = getSubsetShares(shares, getRandomIndexes(k, n));
        // enough shares required
        StepVerifier.create(selectedShares).expectNextCount(k).expectComplete().verify();
        // Recover the secret using the selected shares
        Mono<String> recoveredSecret = secretSharing.recoverSecret(selectedShares);
        // Ensure the recovered secret matches the original secret
        StepVerifier.create(recoveredSecret).expectNext(secret).expectComplete().verify();
    }

    @ParameterizedTest
    @MethodSource("validKAndNLargeValues")
    public void splitSecretAndRecover_Valid_K_N_LargeParameters(int k, int n)
            throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {

        // override default init values
        bitSize = 256;
        maxByteSize = ((bitSize - 1) / 8);
        prime = BigInteger.probablePrime(bitSize, random);
        secretSharing = new SecretSharingImpl(maxShares, prime, random, bitSize, maxByteSize, keyPair, signature);

        String secret = "Little Secret...\n\n42";
        // Split the secret into shares
        shares = secretSharing.splitSecret(k, n, secret);
        // number of generated shares is correct
        StepVerifier.create(shares).expectNextCount(n).expectComplete().verify();
        // Select k shares for secret recovery
        Flux<SecretShareDTO> selectedShares = getSubsetShares(shares, getRandomIndexes(k, n));
        // enough shares required
        StepVerifier.create(selectedShares).expectNextCount(k).expectComplete().verify();
        // Recover the secret using the selected shares
        Mono<String> recoveredSecret = secretSharing.recoverSecret(selectedShares);
        // Ensure the recovered secret matches the original secret
        StepVerifier.create(recoveredSecret).expectNext(secret).expectComplete().verify();
    }

    @Test
    public void splitSecretAndRecover_UnicodeCharactersSecret()
            throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {

        int k = 2, n = 4;
        String secret = "Unicode characters: \u00A9 \u00AE \u260E \u2764";

        // Split the secret into shares
        shares = secretSharing.splitSecret(k, n, secret);
        // number of generated shares is correct
        StepVerifier.create(shares).expectNextCount(n).expectComplete().verify();
        // Select k shares for secret recovery
        Flux<SecretShareDTO> selectedShares = getSubsetShares(shares, getRandomIndexes(k, n));
        // enough shares required
        StepVerifier.create(selectedShares).expectNextCount(k).expectComplete().verify();
        // Recover the secret using the selected shares
        Mono<String> recoveredSecret = secretSharing.recoverSecret(selectedShares);
        // Ensure the recovered secret matches the original secret
        StepVerifier.create(recoveredSecret).expectNext(secret).expectComplete().verify();
    }

    @Test
    public void splitSecretAndRecover_MultilineSecret()
            throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {

        // override default init values
        bitSize = 1024;
        maxByteSize = ((bitSize - 1) / 8);
        prime = BigInteger.probablePrime(bitSize, random);
        secretSharing = new SecretSharingImpl(maxShares, prime, random, bitSize, maxByteSize, keyPair, signature);

        int k = 3, n = 6;
        String secret = """
                This is a  simple secret message.
                This is a new line
                Some more lines...


                And more
                \tMore
                \t\tAlways more""";

        // Split the secret into shares
        shares = secretSharing.splitSecret(k, n, secret);
        // number of generated shares is correct
        StepVerifier.create(shares).expectNextCount(n).expectComplete().verify();
        // Select k shares for secret recovery
        Flux<SecretShareDTO> selectedShares = getSubsetShares(shares, getRandomIndexes(k, n));
        // enough shares required
        StepVerifier.create(selectedShares).expectNextCount(k).expectComplete().verify();
        // Recover the secret using the selected shares
        Mono<String> recoveredSecret = secretSharing.recoverSecret(selectedShares);
        // Ensure the recovered secret matches the original secret
        StepVerifier.create(recoveredSecret).expectNext(secret).expectComplete().verify();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "As armas e os barões assinalados",
            "Que da ocidental praia Lusitana,",
            "Por mares nunca de antes navegados,",
            "For your eyes only.\n\n\tSuper Top Secret\n\n\t\tTop Secret\n\n\t\t42"
    })
    public void splitSecretAndRecover_SmallSecretAndCustomBitSize(String secret)
            throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {

        // override default init values
        bitSize = 768;
        maxByteSize = ((bitSize - 1) / 8);
        prime = BigInteger.probablePrime(bitSize, random);
        secretSharing = new SecretSharingImpl(maxShares, prime, random, bitSize, maxByteSize, keyPair, signature);

        int k = 3, n = 6;

        // Split the secret into shares
        shares = secretSharing.splitSecret(k, n, secret);
        // number of generated shares is correct
        StepVerifier.create(shares).expectNextCount(n).expectComplete().verify();
        // Select k shares for secret recovery
        Flux<SecretShareDTO> selectedShares = getSubsetShares(shares, getRandomIndexes(k, n));
        // enough shares required
        StepVerifier.create(selectedShares).expectNextCount(k).expectComplete().verify();
        // Recover the secret using the selected shares
        Mono<String> recoveredSecret = secretSharing.recoverSecret(selectedShares);
        // Ensure the recovered secret matches the original secret
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
                    2. If debugging is the process of removing software bugs, then programming must be the process of putting them in.
                    3. Computer science is no more about computers than astronomy is about telescopes.
                    4. The computing scientist's main challenge is not to get confused by the complexities of his own making.
                    5. Elegance is not a dispensable luxury but a quality that decides between success and failure."""
    })
    public void splitSecretAndRecover_LargeSecretAndCustomBitSize(String secret)
            throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {

        // override default init values
        bitSize = 4096;
        maxByteSize = ((bitSize - 1) / 8);
        prime = BigInteger.probablePrime(bitSize, random);
        secretSharing = new SecretSharingImpl(maxShares, prime, random, bitSize, maxByteSize, keyPair, signature);

        int k = 2, n = 4;

        // Split the secret into shares
        shares = secretSharing.splitSecret(k, n, secret);
        // number of generated shares is correct
        StepVerifier.create(shares).expectNextCount(n).expectComplete().verify();
        // Select k shares for secret recovery
        Flux<SecretShareDTO> selectedShares = getSubsetShares(shares, getRandomIndexes(k, n));
        // enough shares required
        StepVerifier.create(selectedShares).expectNextCount(k).expectComplete().verify();
        // Recover the secret using the selected shares
        Mono<String> recoveredSecret = secretSharing.recoverSecret(selectedShares);
        // Ensure the recovered secret matches the original secret
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

        return random.ints(0, n).distinct().limit(k).toArray();
    }

    private Flux<SecretShareDTO> getSubsetShares(Flux<SecretShareDTO> shares, int[] indexes) {
        return shares.filter(share -> IntStream.of(indexes).anyMatch(i -> i == share.getIndex()));
    }

}
