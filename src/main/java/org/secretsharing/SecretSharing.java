package org.secretsharing;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.List;


public interface SecretSharing {

    List<SecretShareDTO> splitSecret(int k, int n, String secret) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException;

    String recoverSecret(List<SecretShareDTO> shares) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException;

}
