package com.factory.client;

import com.factory.config.UsersClientConfig;
import com.factory.openapi.model.UserResponse;
import io.netty.resolver.DefaultAddressResolverGroup;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClient;

@Service
@RequiredArgsConstructor
public class UsersClient {

    private final WebClient client;
    private final UsersClientConfig usersClientConfig;

    @Autowired
    public UsersClient(final UsersClientConfig config) {
        this.usersClientConfig = config;
        client = WebClient.builder()
                .baseUrl(usersClientConfig.getUrl())
                .clientConnector(new ReactorClientHttpConnector(
                                HttpClient.create()
                                        .resolver(DefaultAddressResolverGroup.INSTANCE)
                        )
                ).build();
    }

    public Mono<UserResponse> getUserDetails(final String userName) {
        return client.get()
                .uri(usersClientConfig.getUserDetailsPath(), userName)
                .retrieve()
                .bodyToMono(UserResponse.class);
    }
}
