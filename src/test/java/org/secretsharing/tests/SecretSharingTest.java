package org.secretsharing.tests;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.secretsharing.SecretSharing;
import org.secretsharing.SecretSharingImpl;
import org.secretsharing.SecretShareDTO;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertThrows;

public class SecretSharingTest {

    private static final int MIN_BIT_SIZE = 512, MAX_BIT_SIZE = 4096;

    private SecretSharing secretSharing;
    private List<SecretShareDTO> shares;


    @BeforeEach
    public void setupInit() throws NoSuchAlgorithmException {
        secretSharing = new SecretSharingImpl();
        shares = new ArrayList<>();
    }

    @AfterEach
    public void setupDestroy() {
        if (!shares.isEmpty()) {
            shares.clear();
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {Integer.MIN_VALUE, 0, 1, -1, 511, 4097, Integer.MAX_VALUE})
    public void constructor_InvalidArgs(int bitSize) {

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
            () -> secretSharing = new SecretSharingImpl(bitSize));
        Assertions.assertEquals("Bit size value must be between " + MIN_BIT_SIZE + " and " + MAX_BIT_SIZE,
            ex.getMessage());

    }

    @Test
    public void splitSecret_NullOrEmptySecret() {

        assertThrows(IllegalArgumentException.class, () -> shares = secretSharing.splitSecret(4, 9, null));

        assertThrows(IllegalArgumentException.class, () -> shares = secretSharing.splitSecret(4, 9, ""));

        assertThrows(IllegalArgumentException.class,
            () -> shares = secretSharing.splitSecret(4, 9, "\n\t\t\n   \n\t  "));
    }

    @ParameterizedTest
    @MethodSource("invalidKAndNValues")
    public void splitSecret_Invalid_K_N_Parameters(int k, int n) {

        assertThrows(IllegalArgumentException.class,
            () -> shares = secretSharing.splitSecret(k, n, "For your eyes only."));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "Hello\uD800World!",
        "This is a test\uDC00"
    })
    public void splitSecret_InvalidUnicodeCharactersInSecret(String secret) {

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
            () -> shares = secretSharing.splitSecret(3, 7, secret));

        Assertions.assertEquals("Invalid character(s) in secret.", ex.getMessage());

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
    public void splitSecret_SecretOverflow(String secret) {

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
            () -> shares = secretSharing.splitSecret(2, 4, secret));

        Assertions.assertEquals("Secret byte size overflow for current bit size.", ex.getMessage());
    }




    @ParameterizedTest
    @MethodSource("validKAndNValues")
    public void splitSecretAndRecover_Valid_K_N_Parameters(int k, int n) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {

        String secret = "For your eyes only...\n\nAbove Super Top Secret\nSuper Top Secret\nTop Secret\nSecret\n42";

        // Split the secret into shares
        shares = secretSharing.splitSecret(k, n, secret);
        // number of generated shares is correct
        Assertions.assertEquals(n, shares.size());
        // Select k random shares for secret recovery
        List<SecretShareDTO> selectedShares = getSubsetShares(shares, getRandomIndexes(k, n));
        // enough shares required
        Assertions.assertEquals(k, selectedShares.size());
        // Recover the secret using the selected shares
        String recoveredSecret = secretSharing.recoverSecret(selectedShares);
        // Ensure the recovered secret matches the original secret
        Assertions.assertEquals(secret, recoveredSecret);
    }

    @Test
    public void splitSecretAndRecover_UnicodeCharactersSecret() throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {

        int k = 2, n = 4;
        String secret = "Unicode characters: \u00A9 \u00AE \u260E \u2764";

        // Split the secret into shares
        shares = secretSharing.splitSecret(k, n, secret);
        // number of generated shares is correct
        Assertions.assertEquals(n, shares.size());
        // Select k shares for secret recovery
        List<SecretShareDTO> selectedShares = getSubsetShares(shares, getRandomIndexes(k, n));
        // enough shares required
        Assertions.assertEquals(k, selectedShares.size());
        // Recover the secret using the selected shares
        String recoveredSecret = secretSharing.recoverSecret(selectedShares);
        // Ensure the recovered secret matches the original secret
        Assertions.assertEquals(secret, recoveredSecret);
    }

    @Test
    public void splitSecretAndRecover_MultilineSecret() throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {

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
        Assertions.assertEquals(n, shares.size());
        // Select k shares for secret recovery
        List<SecretShareDTO> selectedShares = getSubsetShares(shares, getRandomIndexes(k, n));
        // enough shares required
        Assertions.assertEquals(k, selectedShares.size());
        // Recover the secret using the selected shares
        String recoveredSecret = secretSharing.recoverSecret(selectedShares);
        // Ensure the recovered secret matches the original secret
        Assertions.assertEquals(secret, recoveredSecret);
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "As armas e os barões assinalados",
        "Que da ocidental praia Lusitana,",
        "Por mares nunca de antes navegados,",
        "For your eyes only.\n\n\tSuper Top Secret\n\n\t\tTop Secret\n\n\t\t42"
    })
    public void splitSecretAndRecover_SmallSecretAndCustomBitSize(String secret) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {

        int k = 3, n = 6;
        // custom bitSize constructor
        secretSharing = new SecretSharingImpl(512);
        // Split the secret into shares
        shares = secretSharing.splitSecret(k, n, secret);
        // number of generated shares is correct
        Assertions.assertEquals(n, shares.size());
        // Select k shares for secret recovery
        List<SecretShareDTO> selectedShares = getSubsetShares(shares, getRandomIndexes(k, n));
        // enough shares required
        Assertions.assertEquals(k, selectedShares.size());
        // Recover the secret using the selected shares
        String recoveredSecret = secretSharing.recoverSecret(selectedShares);
        // Ensure the recovered secret matches the original secret
        Assertions.assertEquals(secret, recoveredSecret);
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
    public void splitSecretAndRecover_LargeSecretAndCustomBitSize(String secret) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {

        int k = 3, n = 6;
        // custom bitSize constructor
        secretSharing = new SecretSharingImpl(4096);
        // Split the secret into shares
        shares = secretSharing.splitSecret(k, n, secret);
        // number of generated shares is correct
        Assertions.assertEquals(n, shares.size());
        // Select k shares for secret recovery
        List<SecretShareDTO> selectedShares = getSubsetShares(shares, getRandomIndexes(k, n));
        // enough shares required
        Assertions.assertEquals(k, selectedShares.size());
        // Recover the secret using the selected shares
        String recoveredSecret = secretSharing.recoverSecret(selectedShares);
        // Ensure the recovered secret matches the original secret
        Assertions.assertEquals(secret, recoveredSecret);
    }

    private static Stream<Arguments> validKAndNValues() {
        return Stream.of(
            Arguments.of(1, 1),
            Arguments.of(1, 2),
            Arguments.of(2, 2),
            Arguments.of(15, 30),
            Arguments.of(30, 60));
    }

    private static Stream<Arguments> invalidKAndNValues() {
        return Stream.of(
            Arguments.of(0, 0),
            Arguments.of(0, 1),
            Arguments.of(1, 0),
            Arguments.of(2, 61));
    }

    private static int[] getRandomIndexes(int k, int n) {

        return new Random().ints(0, n).distinct().limit(k).toArray();
    }

    private static List<SecretShareDTO> getSubsetShares(List<SecretShareDTO> shares, int[] indexes) {
        return shares.stream()
            .filter(share -> IntStream.of(indexes).anyMatch(i -> i == share.getIndex()))
            .collect(Collectors.toList());
    }
}
