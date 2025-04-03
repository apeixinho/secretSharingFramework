package org.secretsharing.service;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.List;

import org.secretsharing.model.SecretShareDTO;


public interface SecretSharing {

    List<SecretShareDTO> splitSecret(int k, int n, String secret) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, IllegalArgumentException;

    String recoverSecret(List<SecretShareDTO> shares)  throws SignatureException, InvalidKeyException, SecurityException, IllegalArgumentException;

}
