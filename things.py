# pylint: disable=invalid-name
# things.py

# Let's get this party started.
import sys
import logging

from passlib.hash import sha256_crypt

import falcon
import falcon_jwt


LOGGER = logging.getLogger()
LOGGER.setLevel(logging.DEBUG)

ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
LOGGER.addHandler(ch)

# Just for testing
USERS = {
    "john@john.co":
    {
        "email": "john@john.co",
        "password": sha256_crypt.encrypt("john_is_cool")
    }
}


class ThingsResource(object):

    def on_get(self, req, resp): # pylint: disable=unused-argument,no-self-use
        logging.debug("Reached on_get()")
        resp.status = falcon.HTTP_200  # This is the default status
        resp.body = ('\nTwo things awe me most, the starry sky '
                     'above me and the moral law within me.\n'
                     '\n'
                     '    ~ Immanuel Kant\n\n')


COOKIE_OPTS = {"name": "my_auth_token",
               "max_age": 86400,
               "path": "/things",
               "http_only": True}

login, auth_middleware = falcon_jwt.get_auth_objects(
    USERS.get,
    "UPe6Qqp8xJeRyavxup8GzMTYT6yDwYND", # random secret
    3600,
    token_opts=COOKIE_OPTS
)


# Insert auth_middleware
app = falcon.API(middleware=[auth_middleware])

things = ThingsResource()

app.add_route('/things', things)

# Add login resource
app.add_route('/login', login)

# Good to go!
