package org.secretsharing;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class SecretSharingImpl implements SecretSharing {

    private static final String HASH_ALGORITHM = "SHA256withRSA";
    private static final String ASYMMETRIC_ALGORITHM = "RSA";
    private static final int MIN_BIT_SIZE = 1024, DEFAULT_BIT_SIZE = 2048, MAX_BIT_SIZE = 4096;
    private static final int MAX_SHARES = 60;
    private final BigInteger prime;
    private final SecureRandom random;
    private final int bitSize;
    private final int maxByteSize;
    private final KeyPair keyPair;
    private final Signature signatureVerifier;

    public SecretSharingImpl() throws NoSuchAlgorithmException {
        this(DEFAULT_BIT_SIZE);
    }

    public SecretSharingImpl(int bitSize) throws NoSuchAlgorithmException {
        if (bitSize < MIN_BIT_SIZE || bitSize > MAX_BIT_SIZE) {
            throw new IllegalArgumentException(
                    "Bit size value must be between " + MIN_BIT_SIZE + " and " + MAX_BIT_SIZE);
        }
        this.random = new SecureRandom();
        this.bitSize = bitSize;
        this.maxByteSize = (bitSize - 1) / 8;
        this.prime = BigInteger.probablePrime(bitSize, random);

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ASYMMETRIC_ALGORITHM);
        keyPairGenerator.initialize(bitSize);
        this.keyPair = keyPairGenerator.generateKeyPair();
        this.signatureVerifier = Signature.getInstance(HASH_ALGORITHM);
    }

    @Override
    public List<SecretShareDTO> splitSecret(int k, int n, String secret) throws SignatureException, InvalidKeyException {
        if (k <= 0 || n <= 0 || k > n || n > MAX_SHARES || secret == null || secret.isBlank()) {
            throw new IllegalArgumentException("Invalid parameter(s) provided.");
        }
        // Reject ill-formed UTF-16 (unpaired surrogates); UTF-8 encodes all valid Unicode scalars.
        if (containsUnpairedSurrogate(secret)) {
            throw new IllegalArgumentException("Invalid character(s) in secret.");
        }
        // Ensure that the length of the secret, when encoded in bytes,
        // does not exceed the maximum size allowed by the chosen bit size.
        if (secret.getBytes(StandardCharsets.UTF_8).length > maxByteSize) {
            throw new IllegalArgumentException("Secret byte size overflow for current bit size.");
        }

        List<SecretShareDTO> shares = new ArrayList<>();

        BigInteger[] coefficients = new BigInteger[k];
        // signum=1: treat UTF-8 bytes as an unsigned magnitude (new BigInteger(byte[]) is signed).
        coefficients[0] = new BigInteger(1, secret.getBytes(StandardCharsets.UTF_8));

        for (int i = 1; i < k; i++) {
            // Uniform random field element in [0, p); primality is not required for SSS coeffs.
            coefficients[i] = new BigInteger(bitSize, random).mod(prime);
        }

        // Evaluate at x = 1..n so P(0) = secret is never distributed as a share.
        for (int i = 1; i <= n; i++) {
            BigInteger x = BigInteger.valueOf(i);
            BigInteger y = computePolynomial(coefficients, x);
            shares.add(new SecretShareDTO(i, y, signData(y.toByteArray())));
        }
        return shares;
    }

    @Override
    public String recoverSecret(List<SecretShareDTO> shares) throws SignatureException, InvalidKeyException {
        if (shares == null || shares.isEmpty()) {
            throw new IllegalArgumentException("Empty shares provided.");
        }

        int k = shares.size();

        BigInteger[] xValues = new BigInteger[k];
        BigInteger[] yValues = new BigInteger[k];

        int index = 0;
        for (SecretShareDTO share : shares) {
            xValues[index] = BigInteger.valueOf(share.index());
            yValues[index] = share.share();
            // Verify the signature
            if (!verifySignature(share.share().toByteArray(), share.signature())) {
                throw new SecurityException("Invalid signature for share at index: " + share.index());
            }
            index++;
        }
        BigInteger secret = interpolate(xValues, yValues);

        return new String(unsignedBytesFrom(secret), StandardCharsets.UTF_8);
    }

    /**
     * Inverse of {@code new BigInteger(1, bytes)}: drop the extra leading {@code 0x00} that
     * {@link BigInteger#toByteArray()} may prepend so the value stays non-negative.
     */
    private static byte[] unsignedBytesFrom(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) {
            return Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        return bytes;
    }

    private BigInteger computePolynomial(BigInteger[] coefficients, BigInteger x) {
        BigInteger result = BigInteger.ZERO;

        for (int i = coefficients.length - 1; i >= 0; i--) {
            result = result.multiply(x).add(coefficients[i]).mod(prime);
        }

        return result;
    }

    private BigInteger interpolate(BigInteger[] xValues, BigInteger[] yValues) {
        BigInteger result = BigInteger.ZERO;

        for (int i = 0; i < xValues.length; i++) {
            BigInteger numerator = BigInteger.ONE;
            BigInteger denominator = BigInteger.ONE;

            for (int j = 0; j < xValues.length; j++) {
                if (i != j) {
                    numerator = numerator.multiply(BigInteger.ZERO.subtract(xValues[j])).mod(prime);
                    denominator = denominator.multiply(xValues[i].subtract(xValues[j])).mod(prime);
                }
            }

            BigInteger inverseDenominator = denominator.modInverse(prime);
            BigInteger term = yValues[i].multiply(numerator).multiply(inverseDenominator).mod(prime);

            result = result.add(term).mod(prime);
        }

        return result;
    }

    private static boolean containsUnpairedSurrogate(String value) {
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (Character.isHighSurrogate(c)) {
                if (i + 1 >= value.length() || !Character.isLowSurrogate(value.charAt(i + 1))) {
                    return true;
                }
                i++;
            } else if (Character.isLowSurrogate(c)) {
                return true;
            }
        }
        return false;
    }

    private synchronized byte[] signData(byte[] data) throws InvalidKeyException, SignatureException {
        signatureVerifier.initSign(keyPair.getPrivate());
        signatureVerifier.update(data);
        return signatureVerifier.sign();
    }

    private synchronized boolean verifySignature(byte[] data, byte[] signature)
            throws InvalidKeyException, SignatureException {
        signatureVerifier.initVerify(keyPair.getPublic());
        signatureVerifier.update(data);
        return signatureVerifier.verify(signature);
    }

}
