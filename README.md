# Front service

## Description

Responsibilities of this module are following:
* being the api gateway which routes requests to other modules
* exposes endpoints publicly
* securing APIs which are present in other modules
* exposes log in endpoints

This module has web flux based security configuration. Access to secured endpoints are possible by providing jwt tokens in requests headers. It has endpoints which serve to acquire access and refresh tokens.

Api specification is present in `api-store` project under `login` prefix.

## Configuration

### Create account configuration

#### Enabled
* config.createAccount.enabled
* If `true`, then creating account is enabled

#### From path
* config.createAccount.fromPath
* Users management source path which is present in users service

#### To path
* config.createAccount.toPath
* Users management target path which is present in front service

#### Target service
* config.createAccount.targetService
* Users service url

### Tokens configuration

#### Access token acquirable path
* config.createAccount.accessTokenAcquirablePaths
* List of paths which don't require access token present in request headers

#### Jwt secret
* jwt.jwtSecret
* Value of jwt secret which is used to generate tokens

#### Access token expiration time
* jwt.jwtAccessTokenExpirationInMs
* Time in ms after which access token will expire

#### Refresh token expiration time
* jwt.jwtRefreshTokenExpirationInMs
* Time in ms after which refresh token will expire

### Public paths config

#### Public paths
* config.publicPaths
* Paths which are public and access to them does not require access token

### Clients configuration

#### Public paths
* clients.user.url
* Url to users service

#### Public paths
* clients.user.userDetailsPath
* Path in users service which is responsible for acquiring users details

### Login configuration

#### Max attempts
* login.maxAttempts
* Amount of attempts after which login possibility for given user will be blocked for time described under `config.renewInMinutes` property

#### Renew in minutes
* login.renewInMinutes
* Time of login block
