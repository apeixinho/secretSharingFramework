package org.secretsharing.config;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class CryptographyConfiguration {

    @Value("${secret-sharing.hashAlgorithm:SHA256withRSA}")
    private String hashAlgorithm;

    @Value("${secret-sharing.asymmetricAlgorithm:RSA}")
    private String asymmetricAlgorithm;

    @Value("${secret-sharing.keyPairBitSize:2048}")
    private int keyPairBitSize;

    @Value("${secret-sharing.bitSize:2048}")
    private int bitSize;

    @Value("${secret-sharing.maxShares:300}")
    private int maxShares;

    @Bean
    public KeyPair secretSharingKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(asymmetricAlgorithm);
        keyPairGenerator.initialize(keyPairBitSize);
        return keyPairGenerator.generateKeyPair();
    }

    @Bean
    public Signature secretSharingSignature() throws NoSuchAlgorithmException {
        return Signature.getInstance(hashAlgorithm);
    }

    @Bean
    public SecureRandom secretSharingRandom() {
        return new SecureRandom();
    }

    @Bean
    public BigInteger secretSharingPrime(@Value("${secret-sharing.bitSize:2048}") int bitSize) {
        return BigInteger.probablePrime(bitSize, secretSharingRandom());
    }

    @Bean
    public Integer bitSize() {
        return bitSize;
    }

    @Bean
    public Integer maxByteSize(@Value("${secret-sharing.bitSize:2048}") int bitSize) {
        return (bitSize - 1) / 8;
    }

    @Bean
    public Integer maxShares() {
        return maxShares;
    }

}
