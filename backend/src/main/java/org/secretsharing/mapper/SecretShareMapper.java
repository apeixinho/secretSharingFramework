package org.secretsharing.mapper;

import java.math.BigInteger;

import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.MappingConstants;
import org.mapstruct.Named;
import org.secretsharing.domain.SecretShare;
import org.secretsharing.model.SecretShareDTO;

@Mapper(componentModel = MappingConstants.ComponentModel.SPRING)
public interface SecretShareMapper {

	@Mapping(target = "share", source = "share", qualifiedByName = "stringToBigInteger")
	SecretShareDTO secretShareToSecretShareDTO(SecretShare secretShare);

	@Mapping(target = "share", source = "share", qualifiedByName = "bigIntegerToString")
	SecretShare secretShareDtoToSecretShare(SecretShareDTO secretShareDTO);

	@Named("bigIntegerToString")
	default String bigIntegerToString(BigInteger value) {
		return value == null ? null : value.toString();
	}

	@Named("stringToBigInteger")
	default BigInteger stringToBigInteger(String value) {
		return value == null ? null : new BigInteger(value);
	}
}
