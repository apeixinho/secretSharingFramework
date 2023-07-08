package org.secretsharing;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.List;

public class SecretSharingImpl implements SecretSharing {

    private static final String HASH_ALGORITHM = "SHA256withRSA";
    private static final String ASYMMETRIC_ALGORITHM = "RSA";
    private static final int MIN_BIT_SIZE = 512, DEFAULT_BIT_SIZE = 1024, MAX_BIT_SIZE = 4096;
    private static final int MAX_SHARES = 60;
    private final BigInteger prime;
    private final SecureRandom random;
    private int bitSize = DEFAULT_BIT_SIZE;
    private int maxByteSize = (bitSize - 1) / 8;
    private static KeyPair keyPair;
    private static Signature signatureVerifier;

    public SecretSharingImpl() throws NoSuchAlgorithmException {

        this.random = new SecureRandom();
        this.prime = BigInteger.probablePrime(bitSize, random);
        initAsymmetricEncryption();

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
        initAsymmetricEncryption();
    }

    private void initAsymmetricEncryption() throws NoSuchAlgorithmException {

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ASYMMETRIC_ALGORITHM);
        keyPairGenerator.initialize(bitSize);
        keyPair = keyPairGenerator.generateKeyPair();
        signatureVerifier = Signature.getInstance(HASH_ALGORITHM);
    }

    @Override
    public List<SecretShareDTO> splitSecret(int k, int n, String secret) throws SignatureException, InvalidKeyException {
        // sanity checks
        if (k <= 0 || n <= 0 || k > n || n > MAX_SHARES || secret == null || secret.isBlank()
                || secret.trim().isBlank()) {
            throw new IllegalArgumentException();
        }
        // Define the allowed characters in the secret
        Charset allowedCharset = StandardCharsets.UTF_8;
        if (!allowedCharset.newEncoder().canEncode(secret)) {
            throw new IllegalArgumentException("Invalid character(s) in secret.");
        }
        // Ensure that the length of the secret, when encoded in bytes,
        // does not exceed the maximum size allowed by the chosen bit size.
        if (secret.getBytes(StandardCharsets.UTF_8).length > maxByteSize) {
            throw new IllegalArgumentException("Secret byte size overflow for current bit size.");
        }

        List<SecretShareDTO> shares = new ArrayList<>();

        BigInteger[] coefficients = new BigInteger[k];
        coefficients[0] = new BigInteger(secret.getBytes(StandardCharsets.UTF_8));

        for (int i = 1; i < k; i++) {
            coefficients[i] = BigInteger.probablePrime(bitSize, random);
        }

        for (int i = 0; i < n; i++) {
            BigInteger x = BigInteger.valueOf(i);
            BigInteger y = computePolynomial(coefficients, x);
            shares.add(new SecretShareDTO(i, y, signData(y.toByteArray())));
        }
        return shares;
    }

    @Override
    public String recoverSecret(List<SecretShareDTO> shares) throws  SignatureException, InvalidKeyException {

        if (shares.isEmpty()) {
            throw new IllegalArgumentException();
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

        return new String(secret.toByteArray(), StandardCharsets.UTF_8);
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
                    numerator = numerator.multiply(BigInteger.ZERO.subtract(xValues[j]));
                    denominator = denominator.multiply(xValues[i].subtract(xValues[j])).mod(prime);
                }
            }

            BigInteger inverseDenominator = denominator.modInverse(prime);
            BigInteger term = yValues[i].multiply(numerator).multiply(inverseDenominator).mod(prime);

            result = result.add(term).mod(prime);
        }

        return result;
    }

    private byte[] signData(byte[] data) throws InvalidKeyException, SignatureException {

        signatureVerifier.initSign(keyPair.getPrivate());
        signatureVerifier.update(data);
        return signatureVerifier.sign();

    }
    private boolean verifySignature(byte[] data, byte[] signature) throws  InvalidKeyException, SignatureException {

            signatureVerifier.initVerify(keyPair.getPublic());
            signatureVerifier.update(data);
            return signatureVerifier.verify(signature);
    }

}
