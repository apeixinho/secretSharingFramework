package org.secretsharing.config;

import java.io.IOException;
import java.util.Base64;

import org.springframework.context.annotation.Configuration;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;

@Configuration
public class SerializerConfiguration {

    public static class ByteArraySerializer extends JsonSerializer<byte[]> {

        @Override
        public void serialize(byte[] value, JsonGenerator gen, SerializerProvider serializers) throws IOException {
            String base64Value = Base64.getEncoder().encodeToString(value);
            gen.writeString(base64Value);
        }
    }

    public static class ByteArrayDeserializer extends JsonDeserializer<byte[]> {

        @Override
        public byte[] deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
            String base64Value = p.getValueAsString();
            return Base64.getDecoder().decode(base64Value);
        }
    }
}