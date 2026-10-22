package org.secretsharing;

import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.util.List;

public interface SecretSharing {

    List<SecretShareDTO> splitSecret(int k, int n, String secret) throws SignatureException, InvalidKeyException;

    String recoverSecret(List<SecretShareDTO> shares) throws SignatureException, InvalidKeyException;

}
