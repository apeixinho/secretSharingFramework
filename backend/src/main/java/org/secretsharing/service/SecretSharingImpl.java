package org.secretsharing.service;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.List;

import org.secretsharing.model.SecretShareDTO;
import org.springframework.stereotype.Service;

@Service
public class SecretSharingImpl implements SecretSharing {

    private final int maxShares;
    private final BigInteger prime;
    private final SecureRandom random;
    private final int bitSize;
    private final int maxByteSize;
    private final KeyPair keyPair;
    private final Signature signatureVerifier;

    public SecretSharingImpl(int maxShares, BigInteger prime, SecureRandom random, int bitSize, int maxByteSize,
            KeyPair keyPair, Signature signatureVerifier) {
        this.maxShares = maxShares;
        this.prime = prime;
        this.random = random;
        this.bitSize = bitSize;
        this.maxByteSize = maxByteSize;
        this.keyPair = keyPair;
        this.signatureVerifier = signatureVerifier;
    }

    @Override
    public List<SecretShareDTO> splitSecret(int k, int n, String secret)
            throws SignatureException, InvalidKeyException, IllegalArgumentException {
        // Sanity checks
        if (k <= 0 || n <= 0 || k > n || n > maxShares || secret == null || secret.strip().isBlank()) {
            throw new IllegalArgumentException("Invalid parameter(s) provided.");
        }
        // Define the allowed characters in the secret
        Charset allowedCharset = StandardCharsets.UTF_8;
        if (!allowedCharset.newEncoder().canEncode(secret)) {
            throw new IllegalArgumentException("Invalid character(s) in secret.");
        }
        // Ensure that the length of the secret, when encoded in bytes,
        // does not exceed the maximum size allowed by the chosen bit size
        // add +1 byte for BigInteger sign representation
        int secretBytes = secret.strip().getBytes(StandardCharsets.UTF_8).length + 1;
        if (secretBytes > maxByteSize) {
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
    public String recoverSecret(List<SecretShareDTO> shares)
            throws SignatureException, InvalidKeyException, SecurityException, IllegalArgumentException {

        if (shares.isEmpty()) {
            throw new IllegalArgumentException("Empty shares provided.");
        }

        int k = shares.size();

        BigInteger[] xValues = new BigInteger[k];
        BigInteger[] yValues = new BigInteger[k];

        int index = 0;
        for (SecretShareDTO share : shares) {
            xValues[index] = BigInteger.valueOf(share.getIndex());
            yValues[index] = share.getShare();
            // Verify the signature
            if (!verifySignature(share.getShare().toByteArray(), share.getSignature())) {
                throw new SecurityException("Invalid signature for share at index: " + share.getIndex());
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

    private boolean verifySignature(byte[] data, byte[] signature) throws InvalidKeyException, SignatureException {

        signatureVerifier.initVerify(keyPair.getPublic());
        signatureVerifier.update(data);
        return signatureVerifier.verify(signature);
    }

}
