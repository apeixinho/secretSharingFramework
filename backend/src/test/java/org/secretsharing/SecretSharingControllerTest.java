package org.secretsharing;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.secretsharing.config.SerializerConfiguration;
import org.secretsharing.controller.SecretSharingController;
import org.secretsharing.model.SecretShareDTO;
import org.secretsharing.service.SecretSharing;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(SecretSharingController.class)
@Import(SerializerConfiguration.class)
public class SecretSharingControllerTest {

    @MockBean
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

        // Create a mocked list of shares
        List<SecretShareDTO> mockedShareList = new ArrayList<>(n);
        mockedShareList.add(new SecretShareDTO(1, BigInteger.valueOf(12345), new byte[]{0x01, 0x02, 0x03}));
        mockedShareList.add(new SecretShareDTO(2, BigInteger.valueOf(12345), new byte[]{0x01, 0x02, 0x03}));
        mockedShareList.add(new SecretShareDTO(3, BigInteger.valueOf(12345), new byte[]{0x01, 0x02, 0x03}));
        mockedShareList.add(new SecretShareDTO(4, BigInteger.valueOf(12345), new byte[]{0x01, 0x02, 0x03}));

        // Mock the behavior of the secretSharing.splitSecret() method
        when(secretSharing.splitSecret(anyInt(), anyInt(), anyString())).thenReturn(mockedShareList);

        // Create a request and invoke the splitSecret() method on the controller
        MockHttpServletRequestBuilder request = MockMvcRequestBuilders.get("/api/v1/splitSecret").param("k", String.valueOf(k)).param("n", String.valueOf(n)).param("secret", secret);

        // Perform the request and assert the response
        // "AQID" is the Base64-encoded string representation of the byte array [0x01,0x02, 0x03]
        mockMvc.perform(request).andExpect(status().isOk()).andExpect(jsonPath("$", hasSize(4))).andExpect(jsonPath("$[0].index", equalTo(1))).andExpect(jsonPath("$[0].share", equalTo("12345"))).andExpect(jsonPath("$[0].signature", equalTo("AQID"))).andExpect(jsonPath("$[1].index", equalTo(2))).andExpect(jsonPath("$[1].share", equalTo("12345"))).andExpect(jsonPath("$[1].signature", equalTo("AQID"))).andExpect(jsonPath("$[2].index", equalTo(3))).andExpect(jsonPath("$[2].share", equalTo("12345"))).andExpect(jsonPath("$[2].signature", equalTo("AQID"))).andExpect(jsonPath("$[3].index", equalTo(4))).andExpect(jsonPath("$[3].share", equalTo("12345"))).andExpect(jsonPath("$[3].signature", equalTo("AQID")));

        // Verify that the method was called with the correct parameters
        verify(secretSharing, times(1)).splitSecret(eq(k), eq(n), eq(secret));
    }

    @Test
    public void testRecoverSecret() throws Exception {

        List<SecretShareDTO> shareList = new ArrayList<>();
        shareList.add(new SecretShareDTO(1, BigInteger.valueOf(12345), new byte[]{0x01, 0x02, 0x03}));
        shareList.add(new SecretShareDTO(2, BigInteger.valueOf(54321), new byte[]{0x04, 0x05, 0x06}));

        // Create an argument captor for SecretShare
        ArgumentCaptor<List<SecretShareDTO>> secretShareCaptor = ArgumentCaptor.forClass(List.class);

        // Mock the behavior of the secretSharing.recoverSecret() method
        String recoveredSecret = "Recovered Secret";
        when(secretSharing.recoverSecret(secretShareCaptor.capture())).thenReturn(recoveredSecret);

        // Create a request and invoke the recoverSecret() method on the controller
        MockHttpServletRequestBuilder request = MockMvcRequestBuilders.post("/api/v1/recoverSecret").contentType(MediaType.APPLICATION_JSON).content(toJsonString(shareList));

        // Perform the request and assert the response
        MvcResult result = mockMvc.perform(request).andExpect(status().isOk()).andReturn();

        // Get the response content as a string
        String responseContent = result.getResponse().getContentAsString();

        // Assert the response content
        assertEquals(recoveredSecret, responseContent);
        // Verify that the method was called with the correct parameters
        List<SecretShareDTO> capturedShares = secretShareCaptor.getValue();

        verify(secretSharing, times(1)).recoverSecret(eq(capturedShares));
    }

    @ParameterizedTest
    @MethodSource("invalidParameters")
    public void splitSecret_Invalid_Parameters(int k, int n, String secret) throws Exception {

        // Mock the behavior of the secretSharing.splitSecret() method
        when(secretSharing.splitSecret(anyInt(), anyInt(), anyString())).thenThrow(new IllegalArgumentException());

        // Create a request and invoke the splitSecret() method on the controller
        MockHttpServletRequestBuilder request = MockMvcRequestBuilders.get("/api/v1/splitSecret").param("k", String.valueOf(k)).param("n", String.valueOf(n)).param("secret", "Super Secret");

        // Perform the request and assert the response
        // The expected status code is 400 Bad Request
        mockMvc.perform(request).andExpect(status().isBadRequest());

        // Assert that the secretSharing.splitSecret() method was called once
        verify(secretSharing, times(1)).splitSecret(eq(k), eq(n), eq(secret));
    }

    @ParameterizedTest
    @MethodSource("invalidSecret")
    public void splitSecret_Invalid_Secret(int k, int n, String secret) throws Exception {

        // Mock the behavior of the secretSharing.splitSecret() method
        when(secretSharing.splitSecret(anyInt(), anyInt(), anyString())).thenThrow(new IllegalArgumentException());

        // Create a request and invoke the splitSecret() method on the controller
        MockHttpServletRequestBuilder request = MockMvcRequestBuilders.get("/api/v1/splitSecret").param("k", String.valueOf(k)).param("n", String.valueOf(n)).param("secret", "Super Secret");

        // Perform the request and assert the response
        // The expected status code is 400 Bad Request
        mockMvc.perform(request).andExpect(status().isBadRequest());

        // Assert that the secretSharing.splitSecret() method was called once
        verify(secretSharing, times(1)).splitSecret(eq(k), eq(n),any());
    }

    private static Stream<Arguments> invalidParameters() {
        return Stream.of(Arguments.of(0, 0, "Super Secret"), Arguments.of(0, 1, "Super Secret"), Arguments.of(1, 0, "Super Secret"), Arguments.of(4, 3, "Super Secret"), Arguments.of(2, 61, "Super Secret"));
    }

    private static Stream<Arguments> invalidSecret() {
        return Stream.of( Arguments.of(2, 4, ""), Arguments.of(2, 4, "\n\t\t\n   \n\t"), Arguments.of(2, 4, null));
    }


    private static String toJsonString(Object object) throws JsonProcessingException {
        ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.writeValueAsString(object);
    }

}
