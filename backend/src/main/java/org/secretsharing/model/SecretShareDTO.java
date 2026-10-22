package org.secretsharing.model;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Objects;

import org.secretsharing.config.SerializerConfiguration.ByteArrayDeserializer;
import org.secretsharing.config.SerializerConfiguration.ByteArraySerializer;
import org.secretsharing.utils.NotBlankAnnotation;

import tools.jackson.databind.annotation.JsonDeserialize;
import tools.jackson.databind.annotation.JsonSerialize;
import tools.jackson.databind.deser.jdk.NumberDeserializers.BigIntegerDeserializer;
import tools.jackson.databind.ser.std.ToStringSerializer;

public final class SecretShareDTO {

	@NotBlankAnnotation
	private final Integer index;

	@NotBlankAnnotation
	@JsonSerialize(using = ToStringSerializer.class)
	@JsonDeserialize(using = BigIntegerDeserializer.class)
	private final BigInteger share;

	@NotBlankAnnotation
	@JsonSerialize(using = ByteArraySerializer.class)
	@JsonDeserialize(using = ByteArrayDeserializer.class)
	private final byte[] signature;

	public SecretShareDTO(Integer index, BigInteger share, byte[] signature) {
		this.index = index;
		this.share = share;
		this.signature = signature;
	}

	public Integer getIndex() {
		return index;
	}

	public BigInteger getShare() {
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
		if (!(o instanceof SecretShareDTO that)) {
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
		return "SecretShareDTO[index=" + index + ", share=" + share + ", signature=" + Arrays.toString(signature) + "]";
	}
}
