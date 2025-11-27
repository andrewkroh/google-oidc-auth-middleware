# Traefik Google OIDC Auth Middleware

This is a Traefik middleware plugin that authenticates users with Google OpenID
Connect, and then checks that their email address or Google Workspace domain is 
authorized.

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
| oidc.prompt        |                |          | A space-delimited, case-sensitive list of prompts to present the user. Possible values are: `none`, `consent`, `select_account`. See [Google's docs](https://developers.google.com/identity/protocols/oauth2/web-server#httprest_1) for more info. |
| cookie.name        | oidc_auth      |          | Name of the cookie. It can be customized to avoid collisions when running multiple instances of the middleware.                                                                   |
| cookie.path        | /              |          | You can use this to limit the scope of the cookie to a specific path. Defaults to '/'.                                                                                            |
| cookie.secret      |                | X        | Secret is the HMAC key for cookie signing, and helps provide integrity protection for cookies.                                                                                    |
| cookie.duration    | 24h            |          | Validity period for new cookies. Users are granted access for this length of time regardless of changes to user's account in the OIDC provider. Uses the Go time.Duration format. |
| cookie.insecure    | false          |          | Set to true to omit the `Secure` attribute from cookies.                                                                                                                          |
| cookie.sameSite    | Lax            |          | SameSite attribute for cookies. Options: `Strict`, `Lax`, `None`. `Lax` provides CSRF protection while allowing cookies on top-level navigation.                                  |
| authorized.emails  |                | X        | List of allowed email addresses.                                                                                                                                                  |
| authorized.domains |                | X        | List of allowed domains.                                                                                                                                                          |
| debug              | false          |          | Enable debug logging to stdout.

## Headers

*X-Forwarded-User*

When the middleware proxies a request it adds an `X-Fowarded-User` header
containing the user's email address. This can be used by the downstream service
to identify the authenticated user.

If you want your JSON access logs to include the user's email address then
configure the access log to retain the `X-Forwarded-User` header. Here is a
CLI example:

```
# Adding X-Forwarded-User to JSON access logs.
--accesslog
--accesslog.format=json
--accesslog.fields.headers.names.X-Forwarded-User=keep
```

The resulting access log will contain a `request_X-Forwarded-User` field.

```json
    "request_X-Forwarded-User": "name@gmail.com"
```

See [Limiting the Fields/Including Headers](https://doc.traefik.io/traefik/observability/access-logs/#limiting-the-fieldsincluding-headers) for more details.


## Example config

Static config

```yaml
# traefik.yml

experimental:
  plugins:
    google-oidc-auth-middleware:
      moduleName: "github.com/andrewkroh/google-oidc-auth-middleware"
      # Populate this with the latest release tag.
      version: vX.Y.Z
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
