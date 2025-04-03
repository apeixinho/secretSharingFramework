package org.secretsharing.domain;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.math.BigInteger;

@Data
@AllArgsConstructor
@Builder
@Document
public class SecretShare {

    @Id
    private final Integer index;

    private final BigInteger share;

    private final byte[] signature;
}
