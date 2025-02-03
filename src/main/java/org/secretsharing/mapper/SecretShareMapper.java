package org.secretsharing.mapper;

import org.mapstruct.Mapper;
import org.secretsharing.domain.SecretShare;
import org.secretsharing.model.SecretShareDTO;

@Mapper
public interface SecretShareMapper {

    SecretShareDTO secretShareToSecretShareDTO(SecretShare secretShare);

    SecretShare secretShareDtoToSecretShare(SecretShareDTO secretShareDTO);

}
