package org.secretsharing.config;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import reactor.core.publisher.Mono;

/**
 * Simple fixed-window rate limit for recoverSecret to reduce online guessing
 * / brute-force of share combinations.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 20)
public class RecoverRateLimitWebFilter implements WebFilter {

	private static final String RECOVER_PATH = "/api/v1/recoverSecret";

	private final int capacity;
	private final long windowMillis;
	private final Map<String, WindowCounter> counters = new ConcurrentHashMap<>();

	public RecoverRateLimitWebFilter(
			@Value("${secret-sharing.rate-limit.recover.capacity:30}") int capacity,
			@Value("${secret-sharing.rate-limit.recover.window-seconds:60}") int windowSeconds) {
		this.capacity = Math.max(1, capacity);
		this.windowMillis = Math.max(1, windowSeconds) * 1000L;
	}

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
		var request = exchange.getRequest();
		if (request.getMethod() != HttpMethod.POST
				|| !RECOVER_PATH.equals(request.getPath().pathWithinApplication().value())) {
			return chain.filter(exchange);
		}

		String key = clientKey(exchange);
		if (!allow(key)) {
			exchange.getResponse().setStatusCode(HttpStatus.TOO_MANY_REQUESTS);
			exchange.getResponse().getHeaders().setContentType(MediaType.TEXT_PLAIN);
			byte[] body = "Too many recover attempts. Try again later.".getBytes();
			return exchange.getResponse().writeWith(Mono.just(exchange.getResponse().bufferFactory().wrap(body)));
		}
		return chain.filter(exchange);
	}

	private boolean allow(String key) {
		long now = System.currentTimeMillis();
		WindowCounter counter = counters.compute(key, (k, existing) -> {
			if (existing == null || now - existing.windowStart >= windowMillis) {
				return new WindowCounter(now);
			}
			return existing;
		});
		return counter.count.incrementAndGet() <= capacity;
	}

	private static String clientKey(ServerWebExchange exchange) {
		String forwarded = exchange.getRequest().getHeaders().getFirst("X-Forwarded-For");
		if (forwarded != null && !forwarded.isBlank()) {
			return forwarded.split(",")[0].trim();
		}
		if (exchange.getRequest().getRemoteAddress() != null
				&& exchange.getRequest().getRemoteAddress().getAddress() != null) {
			return exchange.getRequest().getRemoteAddress().getAddress().getHostAddress();
		}
		return "unknown";
	}

	private static final class WindowCounter {
		private final long windowStart;
		private final AtomicInteger count = new AtomicInteger(0);

		private WindowCounter(long windowStart) {
			this.windowStart = windowStart;
		}
	}
}
