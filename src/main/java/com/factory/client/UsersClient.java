package com.factory.client;

import com.factory.openapi.api.UsersApi;
import org.springframework.cloud.openfeign.FeignClient;

@FeignClient(value = "usersClient", url = "${clients.user.url}")
public interface UsersClient extends UsersApi {
}
