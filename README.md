# Traefik Google OIDC Auth Middleware

This is a Traefik middleware plugin that authenticates users with Google OpenID
Connect, and then checks that their email address is authorized.

## Requirements

- Setup a new project in the Google API console to obtain a client ID and 
client secret. See the [Google developer docs](https://developers.google.com/identity/openid-connect/openid-connect).
- Install the plugin to Traefik using static config.
- Configure the middleware in dynamic config.
- Associate a service to the middleware.

## Configuration

| Option             | Default        | Required | Description                                                                                                                                                                       |
|--------------------|----------------|----------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| oidc.clientID      |                | X        | OAuth client ID                                                                                                                                                                   |
| oidc.clientSecret  |                | X        | OAuth client secret                                                                                                                                                               |
| oidc.callbackPath  | /oidc/callback |          | The path where the OIDC provider will redirect the user after authenticating.                                                                                                     |
| cookie.name        | oidc_auth      |          | Name of the cookie. It can be customized to avoid collisions when running multiple instances of the middleware.                                                                   |
| cookie.path        | /              |          | You can use this to limit the scope of the cookie to a specific path. Defaults to '/'.                                                                                            |
| cookie.secret      |                | X        | Secret is the HMAC key for cookie signing, and helps provide integrity protection for cookies.                                                                                    |
| cookie.duration    | 24h            |          | Validity period for new cookies. Users are granted access for this length of time regardless of changes to user's account in the OIDC provider. Uses the Go time.Duration format. |
| cookie.insecure    | false          |          | Set to true to omit the `Secure` attribute from cookies.                                                                                                                          |
| authorized.emails  |                | X        | List of allowed email addresses.                                                                                                                                                  |
| authorized.domains |                | X        | List of allowed domains.                                                                                                                                                          |

## Example config

Static config

```yaml
# traefik.yml

experimental:
  plugins:
    google-oidc-auth-middleware:
      moduleName: "github.com/andrewkroh/google-oidc-auth-middleware"
      version: v0.0.1
```

Dynamic config

```yaml
# dynamic.yml

http:
  middlewares:
    oidc-auth:
      plugin:
        google-oidc-auth-middleware:
          oidc:
            clientID: example.apps.googleusercontent.com
            clientSecret: fake-secret
          cookie:
            secret: mySecretKey
          authorized:
            emails:
              - name@gmail.com
            domains:
              - example.com
  routers:
    my-router:
      rule: host(`localhost`)
      service: service-foo
      entryPoints:
        - web
      middlewares:
        - oidc-auth
```