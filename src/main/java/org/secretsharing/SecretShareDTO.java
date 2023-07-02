package org.secretsharing;

import java.math.BigInteger;

public class SecretShareDTO {
    private final int index;
    private final BigInteger share;
    private final byte[] signature;

    public SecretShareDTO(int index, BigInteger share, byte[] signature) {
        this.index = index;
        this.share = share;
        this.signature = signature;
    }

    public int getIndex() {
        return index;
    }

    public BigInteger getShare() {
        return share;
    }

    public byte[] getSignature() {
        return signature;
    }
}
