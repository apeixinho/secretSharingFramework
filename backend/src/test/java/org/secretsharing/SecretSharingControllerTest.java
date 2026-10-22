package org.secretsharing;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.secretsharing.config.SerializerConfiguration;
import org.secretsharing.controller.ApiExceptionHandler;
import org.secretsharing.controller.SecretSharingController;
import org.secretsharing.model.SecretShareDTO;
import org.secretsharing.service.SecretSharing;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

@WebMvcTest(SecretSharingController.class)
@Import({ SerializerConfiguration.class, ApiExceptionHandler.class })
public class SecretSharingControllerTest {

	@MockitoBean
	SecretSharing secretSharing;

	@Autowired
	MockMvc mockMvc;

	@Test
	public void testSecretSharingControllerDependency() {
		Assertions.assertNotNull(secretSharing);
	}

	@Test
	public void testSplitSecret() throws Exception {
		int k = 2, n = 4;
		String secret = "Super Secret";

		List<SecretShareDTO> mockedShareList = new ArrayList<>(n);
		mockedShareList.add(new SecretShareDTO(1, BigInteger.valueOf(12345), new byte[] { 0x01, 0x02, 0x03 }));
		mockedShareList.add(new SecretShareDTO(2, BigInteger.valueOf(12345), new byte[] { 0x01, 0x02, 0x03 }));
		mockedShareList.add(new SecretShareDTO(3, BigInteger.valueOf(12345), new byte[] { 0x01, 0x02, 0x03 }));
		mockedShareList.add(new SecretShareDTO(4, BigInteger.valueOf(12345), new byte[] { 0x01, 0x02, 0x03 }));

		when(secretSharing.splitSecret(anyInt(), anyInt(), anyString())).thenReturn(mockedShareList);

		MockHttpServletRequestBuilder request = MockMvcRequestBuilders.get("/api/v1/splitSecret")
				.param("k", String.valueOf(k))
				.param("n", String.valueOf(n))
				.param("secret", secret);

		mockMvc.perform(request)
				.andExpect(status().isOk())
				.andExpect(jsonPath("$", hasSize(4)))
				.andExpect(jsonPath("$[0].index", equalTo(1)))
				.andExpect(jsonPath("$[0].share", equalTo("12345")))
				.andExpect(jsonPath("$[0].signature", equalTo("AQID")));

		verify(secretSharing, times(1)).splitSecret(eq(k), eq(n), eq(secret));
	}

	@Test
	public void testRecoverSecret() throws Exception {
		List<SecretShareDTO> shareList = new ArrayList<>();
		shareList.add(new SecretShareDTO(1, BigInteger.valueOf(12345), new byte[] { 0x01, 0x02, 0x03 }));
		shareList.add(new SecretShareDTO(2, BigInteger.valueOf(54321), new byte[] { 0x04, 0x05, 0x06 }));

		ArgumentCaptor<List<SecretShareDTO>> secretShareCaptor = ArgumentCaptor.forClass(List.class);
		String recoveredSecret = "Recovered Secret";
		when(secretSharing.recoverSecret(secretShareCaptor.capture())).thenReturn(recoveredSecret);

		String body = """
				[
				  {"index":1,"share":"12345","signature":"AQID"},
				  {"index":2,"share":"54321","signature":"BAUG"}
				]
				""";

		MockHttpServletRequestBuilder request = MockMvcRequestBuilders.post("/api/v1/recoverSecret")
				.contentType(MediaType.APPLICATION_JSON)
				.content(body);

		MvcResult result = mockMvc.perform(request).andExpect(status().isOk()).andReturn();
		assertEquals(recoveredSecret, result.getResponse().getContentAsString());
		verify(secretSharing, times(1)).recoverSecret(eq(secretShareCaptor.getValue()));
	}

	@ParameterizedTest
	@MethodSource("invalidParameters")
	public void splitSecret_Invalid_Parameters(int k, int n, String secret) throws Exception {
		when(secretSharing.splitSecret(anyInt(), anyInt(), anyString()))
				.thenThrow(new IllegalArgumentException("Invalid parameter(s) provided."));

		MockHttpServletRequestBuilder request = MockMvcRequestBuilders.get("/api/v1/splitSecret")
				.param("k", String.valueOf(k))
				.param("n", String.valueOf(n))
				.param("secret", secret);

		mockMvc.perform(request).andExpect(status().isBadRequest());
	}

	private static Stream<Arguments> invalidParameters() {
		return Stream.of(
				Arguments.of(0, 0, "Super Secret"),
				Arguments.of(0, 1, "Super Secret"),
				Arguments.of(1, 0, "Super Secret"),
				Arguments.of(4, 3, "Super Secret"),
				Arguments.of(2, 61, "Super Secret"));
	}
}
