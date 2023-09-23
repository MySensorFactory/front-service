package com.factory.client;

import com.factory.openapi.model.UserResponse;
import io.netty.resolver.DefaultAddressResolverGroup;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClient;

@Service
@RequiredArgsConstructor
public class UsersClient {

    private final WebClient client;

    @Autowired
    public UsersClient(@Value("${clients.user.url}") final String userClientUrl) {
        client = WebClient.builder()
                .baseUrl(userClientUrl)
                .clientConnector(new ReactorClientHttpConnector(
                                HttpClient.create()
                                        .resolver(DefaultAddressResolverGroup.INSTANCE)
                        )
                ).build();
    }

    public Mono<UserResponse> getUserDetails(final String userName) {
        return client.get()
                .uri("/users/{userName}", userName)
                .retrieve()
                .bodyToMono(UserResponse.class);
    }
}
