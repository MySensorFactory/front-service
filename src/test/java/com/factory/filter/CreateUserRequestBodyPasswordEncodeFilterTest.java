package com.factory.filter;

import com.factory.openapi.model.CreateUserRequest;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.server.ServerWebExchange;
import reactor.test.StepVerifier;

@ExtendWith(MockitoExtension.class)
class CreateUserRequestBodyPasswordEncodeFilterTest {

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private ServerWebExchange exchange;

    @Test
    void testApplyWithValidInput() throws Exception {
        CreateUserRequestBodyPasswordEncodeFilter filter = new CreateUserRequestBodyPasswordEncodeFilter(objectMapper, passwordEncoder);
        CreateUserRequest request = new CreateUserRequest();
        request.setPassword("plainPassword");

        Mockito.when(objectMapper.readValue(Mockito.anyString(), Mockito.eq(CreateUserRequest.class)))
                .thenReturn(request);

        Mockito.when(objectMapper.writeValueAsString(Mockito.any(CreateUserRequest.class)))
                .thenAnswer(invocation -> {
                    CreateUserRequest req = invocation.getArgument(0);
                    return "{\"password\":\"" + req.getPassword() + "\"}";
                });

        Mockito.when(passwordEncoder.encode(Mockito.anyString()))
                .thenReturn("encodedPassword");

        StepVerifier.create(filter.apply(exchange, "sampleRequestBody"))
                .expectNext("{\"password\":\"encodedPassword\"}")
                .verifyComplete();
    }

    @Test
    void testApplyWithException() throws Exception {
        CreateUserRequestBodyPasswordEncodeFilter filter = new CreateUserRequestBodyPasswordEncodeFilter(objectMapper, passwordEncoder);

        Mockito.when(objectMapper.readValue(Mockito.anyString(), Mockito.eq(CreateUserRequest.class)))
                .thenThrow(new JsonProcessingException("Simulated exception") {
                });

        StepVerifier.create(filter.apply(exchange, "sampleRequestBody"))
                .verifyError();
    }
}

