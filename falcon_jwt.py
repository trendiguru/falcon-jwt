# This package will provide:
# 1. The LoginResouce. POSTing to this with a valid username and password will send back an Auth Cookie
# 2. Corresponding AuthMiddleware which will only allow logged in users to access resources.


# Let's get this party started.
import sys
from datetime import datetime, timedelta
import traceback
import json
import logging

import falcon
import jwt
from passlib.hash import sha256_crypt

DEFAULT_COOKIE_OPTS = {"name": "auth_token", "place":"holder"}


class LoginResource(object):

    def __init__(self, get_user, secret, token_expiration_seconds, **cookie_opts):
        self.get_user = get_user
        self.secret = secret
        self.token_expiration_seconds = token_expiration_seconds
        self.cookie_opts = cookie_opts or DEFAULT_COOKIE_OPTS
        logging.debug(cookie_opts)

    def on_post(self, req, resp):
        logging.debug("Reached on_post() in Login")
        try:
            data = json.loads(req.stream.read())
        except Exception as e:
            raise falcon.HTTPBadRequest(
                "I don't understand", traceback.format_exc())
        email = data["email"]
        password = data["password"]
        user = self.get_user(email)
        if user and sha256_crypt.verify(password, user["password"]):
            logging.debug("Valid user, jwt'ing!")
            self.add_new_jwtoken(resp, email)
        else:
            raise falcon.HTTPUnauthorized('Who Do You Think You Are?',
                                          'Bad email/password combination, please try again',
                                          ['Hello="World!"'])

    # given a user identifier, this will add a new token to the response
    # Typically you would call this from within your login function, after the
    # back end has OK'd the username/password
    def add_new_jwtoken(self, resp, user_identifier=None):
        # add a JSON web token to the response headers
        if not user_identifier:
            raise Exception('Empty user_identifer passed to set JWT')
        logging.debug(
            "Creating new JWT, user_identifier is: {}".format(user_identifier))
        token = jwt.encode({'user_identifier': user_identifier,
                            'exp': datetime.utcnow() + timedelta(seconds=self.token_expiration_seconds)},
                           self.secret,
                           algorithm='HS256').decode("utf-8")
        logging.debug("Setting COOKIE!")
        self.cookie_opts["value"] = token
        logging.debug(self.cookie_opts)
        resp.set_cookie(**self.cookie_opts)


class AuthMiddleware(object):

    def __init__(self, secret, **cookie_opts):
        self.secret = secret
        self.cookie_opts = cookie_opts or DEFAULT_COOKIE_OPTS

    def process_resource(self, req, resp, resource, params):
        logging.debug("Processing request in AuthMiddleware: ")
        if type(resource) is LoginResource:
            logging.debug("LOGIN, DON'T NEED TOKEN")
            return

        challenges = ['Hello="World"']  # I think this is very irrelevant

        token = req.cookies.get(self.cookie_opts.get("name"))
        if token is None:
            description = ('Please provide an auth token '
                           'as part of the request.')

            raise falcon.HTTPUnauthorized('Auth token required',
                                          description,
                                          challenges,
                                          href='http://docs.example.com/auth')

        if not self._token_is_valid(token):
            description = ('The provided auth token is not valid. '
                           'Please request a new token and try again.')

            raise falcon.HTTPUnauthorized('Authentication required',
                                          description,
                                          challenges,
                                          href='http://docs.example.com/auth')

    def _token_is_valid(self, token):
        try:
            jwt.decode(token, self.secret, algorithm='HS256')
            return True
        except:
            return False


# def get_auth_objects(get_user, secret, token_expiration_seconds=3600,
# cookie_opts=DEFAULT_COOKIE_OPTS):
def get_auth_objects(get_user, secret, token_expiration_seconds, cookie_opts=DEFAULT_COOKIE_OPTS):
    return LoginResource(get_user, secret, token_expiration_seconds, **cookie_opts), AuthMiddleware(secret, **cookie_opts)
