package org.secretsharing;

import java.math.BigInteger;

public record SecretShareDTO(int index, BigInteger share, byte[] signature) {
}
