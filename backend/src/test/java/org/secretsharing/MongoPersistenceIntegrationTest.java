package org.secretsharing;

import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigInteger;
import java.time.Duration;

import org.junit.jupiter.api.Test;
import org.secretsharing.domain.SecretShare;
import org.secretsharing.repository.SecretShareRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.mongodb.MongoDBContainer;

import reactor.test.StepVerifier;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Testcontainers(disabledWithoutDocker = true)
class MongoPersistenceIntegrationTest {

	@Container
	@ServiceConnection
	static MongoDBContainer mongo = new MongoDBContainer("mongo:7.0.5");

	@LocalServerPort
	private int port;

	@Autowired
	private SecretShareRepository secretShareRepository;

	@Test
	void repositoryRoundTripAndMongoHealthUp() {
		SecretShare share = new SecretShare(1, BigInteger.TEN.toString(), new byte[] { 1, 2, 3 });

		StepVerifier.create(secretShareRepository.deleteAll()
				.then(secretShareRepository.save(share))
				.flatMap(saved -> secretShareRepository.findById(saved.getIndex())))
				.assertNext(found -> {
					assertThat(found.getIndex()).isEqualTo(1);
					assertThat(found.getShare()).isEqualTo("10");
					assertThat(found.getSignature()).containsExactly(1, 2, 3);
				})
				.verifyComplete();

		WebTestClient.bindToServer()
				.baseUrl("http://localhost:" + port)
				.responseTimeout(Duration.ofSeconds(15))
				.build()
				.get()
				.uri("/actuator/health")
				.exchange()
				.expectStatus().isOk()
				.expectBody()
				.jsonPath("$.status").isEqualTo("UP");
	}
}
