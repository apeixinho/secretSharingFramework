package org.secretsharing;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = {
		"secret-sharing.mongo-credentials.mongouser=test",
		"secret-sharing.mongo-credentials.mongopass=test",
		"secret-sharing.mongo-credentials.mongodb=test",
		"management.health.defaults.enabled=false",
		"management.health.ping.enabled=true",
		"management.health.mongo.enabled=false"
})
public class SecretSharingApplicationTest {

	@LocalServerPort
	private int port;

	@Test
	void contextLoads() {
	}

	@Test
	void actuatorHealthIsUp() {
		WebTestClient.bindToServer()
				.baseUrl("http://localhost:" + port)
				.responseTimeout(java.time.Duration.ofSeconds(10))
				.build()
				.get()
				.uri("/actuator/health")
				.exchange()
				.expectStatus().isOk()
				.expectBody()
				.jsonPath("$.status").isEqualTo("UP");
	}
}
