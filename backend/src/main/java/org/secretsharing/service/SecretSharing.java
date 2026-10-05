package org.secretsharing.service;

import org.secretsharing.model.SecretShareDTO;
import org.secretsharing.model.SplitSecretRequest;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public interface SecretSharing {

    Flux<SecretShareDTO> splitSecret(SplitSecretRequest request);

    Mono<String> recoverSecret(Flux<SecretShareDTO> shares);
}
