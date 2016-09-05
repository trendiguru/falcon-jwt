# things.py

# Let's get this party started.
import falcon
import json
import traceback
from datetime import datetime, timedelta
import sys
import jwt
from passlib.hash import sha256_crypt

import falcon_jwt

import logging

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

# Just for testing
USERS = {
    "iddan@iddan.co":
    {
        "email": "iddan@iddan.co",
        "password": sha256_crypt.encrypt("iddan_is_cool")
    }
}


# Falcon follows the REST architectural style, meaning (among
# other things) that you think in terms of resources and state
# transitions, which map to HTTP verbs.
class ThingsResource(object):

    def on_get(self, req, resp):
        logging.debug("Reached on_get()")
        resp.status = falcon.HTTP_200  # This is the default status
        resp.body = ('\nTwo things awe me most, the starry sky '
                     'above me and the moral law within me.\n'
                     '\n'
                     '    ~ Immanuel Kant\n\n')


COOKIE_OPTS = {"name": "fzz_auth_token",
               "max_age": 86400,
               "path": "/things",
               "http_only": True}

login, auth_middleware = falcon_jwt.get_auth_objects(
    USERS.get,
    "UPe6Qqp8xJeRyavxup8GzMTYT6yDwYND",
    3600,
    cookie_opts=COOKIE_OPTS
)


# falcon.API instances are callable WSGI apps
app = falcon.API(middleware=[auth_middleware])


# Resources are represented by long-lived class instances
things = ThingsResource()

# things will handle all requests to the '/things' URL path
app.add_route('/things', things)
app.add_route('/login', login)
