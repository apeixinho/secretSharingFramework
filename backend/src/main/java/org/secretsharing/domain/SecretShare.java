package org.secretsharing.domain;

import java.util.Arrays;
import java.util.Objects;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

@Document
public class SecretShare {

	@Id
	private final Integer index;

	/** Decimal string form of the share (BigInteger does not fit Decimal128 for large bit sizes). */
	private final String share;

	private final byte[] signature;

	public SecretShare(Integer index, String share, byte[] signature) {
		this.index = index;
		this.share = share;
		this.signature = signature;
	}

	public Integer getIndex() {
		return index;
	}

	public String getShare() {
		return share;
	}

	public byte[] getSignature() {
		return signature;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (!(o instanceof SecretShare that)) {
			return false;
		}
		return Objects.equals(index, that.index)
				&& Objects.equals(share, that.share)
				&& Arrays.equals(signature, that.signature);
	}

	@Override
	public int hashCode() {
		int result = Objects.hash(index, share);
		result = 31 * result + Arrays.hashCode(signature);
		return result;
	}

	@Override
	public String toString() {
		return "SecretShare[index=" + index + ", share=" + share + ", signature=" + Arrays.toString(signature) + "]";
	}
}
