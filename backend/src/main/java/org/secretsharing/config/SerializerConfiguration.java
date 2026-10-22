package org.secretsharing.config;

import java.util.Base64;

import org.springframework.context.annotation.Configuration;

import tools.jackson.core.JsonGenerator;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.SerializationContext;
import tools.jackson.databind.ValueDeserializer;
import tools.jackson.databind.ValueSerializer;

@Configuration
public class SerializerConfiguration {

	public static class ByteArraySerializer extends ValueSerializer<byte[]> {

		@Override
		public void serialize(byte[] value, JsonGenerator gen, SerializationContext serializers) {
			String base64Value = Base64.getEncoder().encodeToString(value);
			gen.writeString(base64Value);
		}
	}

	public static class ByteArrayDeserializer extends ValueDeserializer<byte[]> {

		@Override
		public byte[] deserialize(JsonParser p, DeserializationContext ctxt) {
			String base64Value = p.getValueAsString();
			return Base64.getDecoder().decode(base64Value);
		}
	}
}
