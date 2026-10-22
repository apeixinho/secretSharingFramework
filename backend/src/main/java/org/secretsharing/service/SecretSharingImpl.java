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

import org.secretsharing.domain.SecretShare;
import org.secretsharing.mapper.SecretShareMapper;
import org.secretsharing.model.SecretShareDTO;
import org.secretsharing.repository.SecretShareRepository;
import org.springframework.stereotype.Service;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

@Service
public class SecretSharingImpl implements SecretSharing {

	private final int maxShares;
	private final BigInteger prime;
	private final SecureRandom random;
	private final int bitSize;
	private final int maxByteSize;
	private final KeyPair keyPair;
	private final Signature signatureVerifier;
	private final SecretShareRepository secretShareRepository;
	private final SecretShareMapper secretShareMapper;

	public SecretSharingImpl(
			int maxShares,
			BigInteger prime,
			SecureRandom random,
			int bitSize,
			int maxByteSize,
			KeyPair keyPair,
			Signature signatureVerifier,
			SecretShareRepository secretShareRepository,
			SecretShareMapper secretShareMapper) {
		this.maxShares = maxShares;
		this.prime = prime;
		this.random = random;
		this.bitSize = bitSize;
		this.maxByteSize = maxByteSize;
		this.keyPair = keyPair;
		this.signatureVerifier = signatureVerifier;
		this.secretShareRepository = secretShareRepository;
		this.secretShareMapper = secretShareMapper;
	}

	@Override
	public Flux<SecretShareDTO> getSecretShares() {
		return secretShareRepository.findAll().map(secretShareMapper::secretShareToSecretShareDTO);
	}

	@Override
	public Flux<SecretShareDTO> splitSecret(int k, int n, String secret) {
		if (k <= 0 || n <= 0 || k > n || n > maxShares || secret == null || secret.strip().isBlank()) {
			return Flux.error(new IllegalArgumentException("Invalid parameter(s) provided."));
		}
		Charset allowedCharset = StandardCharsets.UTF_8;
		if (!allowedCharset.newEncoder().canEncode(secret)) {
			return Flux.error(new IllegalArgumentException("Invalid character(s) in secret."));
		}
		int secretBytes = secret.strip().getBytes(StandardCharsets.UTF_8).length + 1;
		if (secretBytes > maxByteSize) {
			return Flux.error(new IllegalArgumentException("Secret byte size overflow for current bit size."));
		}

		return Mono.fromCallable(() -> doSplitSecret(k, n, secret))
				.subscribeOn(Schedulers.parallel())
				.flatMapMany(this::replacePersistedShares);
	}

	private Flux<SecretShareDTO> replacePersistedShares(List<SecretShareDTO> shares) {
		List<SecretShare> entities = shares.stream().map(secretShareMapper::secretShareDtoToSecretShare).toList();
		return secretShareRepository
				.deleteAll()
				.thenMany(secretShareRepository.saveAll(entities))
				.map(secretShareMapper::secretShareToSecretShareDTO);
	}

	private List<SecretShareDTO> doSplitSecret(int k, int n, String secret)
			throws SignatureException, InvalidKeyException {
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
	public Mono<String> recoverSecret(Flux<SecretShareDTO> shares) {
		return shares.collectList().flatMap(sharesList -> {
			if (sharesList.isEmpty()) {
				return Mono.error(new IllegalArgumentException("Empty shares provided."));
			}
			return Mono.fromCallable(() -> doRecoverSecret(sharesList)).subscribeOn(Schedulers.parallel());
		});
	}

	private String doRecoverSecret(List<SecretShareDTO> shares) throws SignatureException, InvalidKeyException {
		int k = shares.size();

		BigInteger[] xValues = new BigInteger[k];
		BigInteger[] yValues = new BigInteger[k];

		int index = 0;
		for (SecretShareDTO share : shares) {
			xValues[index] = BigInteger.valueOf(share.getIndex());
			yValues[index] = share.getShare();
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
