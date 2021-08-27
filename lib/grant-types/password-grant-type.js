'use strict';

/**
 * Module dependencies.
 */

var AbstractGrantType = require('./abstract-grant-type');
var InvalidArgumentError = require('../errors/invalid-argument-error');
var InvalidGrantError = require('../errors/invalid-grant-error');
var InvalidRequestError = require('../errors/invalid-request-error');
var Promise = require('bluebird');
var promisify = require('promisify-any').use(Promise);
var is = require('../validator/is');
var util = require('util');

/**
 * Constructor.
 */

function PasswordGrantType(options) {
  options = options || {};

  if (!options.model) {
    throw new InvalidArgumentError('Missing parameter: `model`');
  }

  if (!options.model.getUser) {
    throw new InvalidArgumentError('Invalid argument: model does not implement `getUser()`');
  }

  if (!options.model.saveToken) {
    throw new InvalidArgumentError('Invalid argument: model does not implement `saveToken()`');
  }

  AbstractGrantType.call(this, options);
}

/**
 * Inherit prototype.
 */

util.inherits(PasswordGrantType, AbstractGrantType);

PasswordGrantType.prototype.readRequestBody = async (request) => {
    if (['put', 'post', 'delete'].indexOf(request.method.toLowerCase()) === -1) return {}
    const request_clone = request.clone()
    const { headers } = request_clone
    const contentType = headers.get('content-type') || ''
    try{
        if (contentType.includes('application/json')) {
            return await request_clone.json()
        } else if (contentType.indexOf("form") >= 0) {
            const formData = await request_clone.formData();
            const body = {};
            for (const entry of formData.entries()) {
                body[entry[0]] = entry[1]
            }
            return body;
        } else {
            return {}
        }
    } catch (e) {
        return {}
    }
};

/**
 * Retrieve the user from the model using a username/password combination.
 *
 * @see https://tools.ietf.org/html/rfc6749#section-4.3.2
 */

PasswordGrantType.prototype.handle = function(request, client) {
  if (!request) {
    throw new InvalidArgumentError('Missing parameter: `request`');
  }

  if (!client) {
    throw new InvalidArgumentError('Missing parameter: `client`');
  }

  var scope = this.getScope(request);

  return Promise.bind(this)
    .then(function() {
      return this.getUser(request);
    })
    .then(function(user) {
      return this.saveToken(user, client, scope);
    });
};

/**
 * Get user using a username/password combination.
 */

PasswordGrantType.prototype.getUser = async function(request) {
    const body = await this.readRequestBody(request)
  if (!body.username) {
    throw new InvalidRequestError('Missing parameter: `username`');
  }

  if (!body.password) {
    throw new InvalidRequestError('Missing parameter: `password`');
  }

  if (!is.uchar(body.username)) {
    throw new InvalidRequestError('Invalid parameter: `username`');
  }

  if (!is.uchar(body.password)) {
    throw new InvalidRequestError('Invalid parameter: `password`');
  }

  return promisify(this.model.getUser, 2).call(this.model, body.username, body.password)
    .then(function(user) {
      if (!user) {
        throw new InvalidGrantError('Invalid grant: user credentials are invalid');
      }

      return user;
    });
};

/**
 * Save token.
 */

PasswordGrantType.prototype.saveToken = function(user, client, scope) {
  var fns = [
    this.validateScope(user, client, scope),
    this.generateAccessToken(client, user, scope),
    this.generateRefreshToken(client, user, scope),
    this.getAccessTokenExpiresAt(),
    this.getRefreshTokenExpiresAt()
  ];

  return Promise.all(fns)
    .bind(this)
    .spread(function(scope, accessToken, refreshToken, accessTokenExpiresAt, refreshTokenExpiresAt) {
      var token = {
        accessToken: accessToken,
        accessTokenExpiresAt: accessTokenExpiresAt,
        refreshToken: refreshToken,
        refreshTokenExpiresAt: refreshTokenExpiresAt,
        scope: scope
      };

      return promisify(this.model.saveToken, 3).call(this.model, token, client, user);
    });
};

/**
 * Export constructor.
 */

module.exports = PasswordGrantType;
