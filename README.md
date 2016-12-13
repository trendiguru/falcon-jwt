# falcon-jwt
Middleware and Login Resource for securing you falcon API with JSON Web Tokens.


This package provides:

1.  The LoginResouce. POSTing to this with a valid username and password will send back an Auth Cookie
2.  Corresponding AuthMiddleware which will only allow logged in users to access resources.

Should be configured to pass pylint with a simple py.test --pylint

See https://github.com/trendiguru/falcon-jwt/blob/master/things.py for a usage example.
