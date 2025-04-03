package org.secretsharing.model;

import java.math.BigInteger;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.databind.deser.std.NumberDeserializers.BigIntegerDeserializer;
import com.fasterxml.jackson.databind.ser.std.ToStringSerializer;

import org.secretsharing.config.SerializerConfiguration.ByteArrayDeserializer;
import org.secretsharing.config.SerializerConfiguration.ByteArraySerializer;
import org.secretsharing.utils.NotBlankAnnotation;

import lombok.Data;
import lombok.RequiredArgsConstructor;

@Data
@RequiredArgsConstructor
public class SecretShareDTO {

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

}
