package org.secretsharing.repository;

import org.secretsharing.domain.SecretShare;
import org.springframework.data.mongodb.repository.ReactiveMongoRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public interface SecretShareRepository extends ReactiveMongoRepository<SecretShare, Integer> {

    Mono<SecretShare> findSecretShareByIndex(Integer index);

    Flux<SecretShare> findAll();

}
