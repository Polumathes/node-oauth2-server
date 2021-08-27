'use strict';

/**
 * Module dependencies.
 */

var BearerTokenType = require('../token-types/bearer-token-type');
var InvalidArgumentError = require('../errors/invalid-argument-error');
var InvalidClientError = require('../errors/invalid-client-error');
var InvalidRequestError = require('../errors/invalid-request-error');
var OAuthError = require('../errors/oauth-error');
var Promise = require('bluebird');
var promisify = require('promisify-any').use(Promise);
var ServerError = require('../errors/server-error');
var TokenModel = require('../models/token-model');
var UnauthorizedClientError = require('../errors/unauthorized-client-error');
var UnsupportedGrantTypeError = require('../errors/unsupported-grant-type-error');
var auth = require('basic-auth');
var is = require('../validator/is');

/**
 * Grant types.
 */

var grantTypes = {
  authorization_code: require('../grant-types/authorization-code-grant-type'),
  client_credentials: require('../grant-types/client-credentials-grant-type'),
  password: require('../grant-types/password-grant-type'),
  refresh_token: require('../grant-types/refresh-token-grant-type')
};

/**
 * Constructor.
 */

function TokenHandler(options) {
  options = options || {};

  if (!options.accessTokenLifetime) {
    throw new InvalidArgumentError('Missing parameter: `accessTokenLifetime`');
  }

  if (!options.model) {
    throw new InvalidArgumentError('Missing parameter: `model`');
  }

  if (!options.refreshTokenLifetime) {
    throw new InvalidArgumentError('Missing parameter: `refreshTokenLifetime`');
  }

  if (!options.model.getClient) {
    throw new InvalidArgumentError('Invalid argument: model does not implement `getClient()`');
  }

  this.accessTokenLifetime = options.accessTokenLifetime;
  this.grantTypes = { ...grantTypes, ...options.extendedGrantTypes };
  this.model = options.model;
  this.refreshTokenLifetime = options.refreshTokenLifetime;
  this.allowExtendedTokenAttributes = options.allowExtendedTokenAttributes;
  this.requireClientAuthentication = options.requireClientAuthentication || {};
  this.alwaysIssueNewRefreshToken = options.alwaysIssueNewRefreshToken !== false;
}

/**
 * Token Handler.
 */

TokenHandler.prototype.readRequestBody = async (request) => {
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

TokenHandler.prototype.handle = async function(request, response) {
  if (!(request instanceof Request)) {
    throw new InvalidArgumentError('Invalid argument: `request` must be an instance of Request');
  }

  if (!(response instanceof Response)) {
    throw new InvalidArgumentError('Invalid argument: `response` must be an instance of Response');
  }

  if (request.method !== 'POST') {
    return Promise.reject(new InvalidRequestError('Invalid request: method must be POST'));
  }

  const content_type = request.headers.get('content-type')
  if ( content_type !== null && content_type !== 'application/x-www-form-urlencoded') {
    return Promise.reject(new InvalidRequestError('Invalid request: content must be application/x-www-form-urlencoded'));
  }
    try{
        const client = await this.getClient(request, response)
        const grantType = await this.handleGrantType(request, client)
        var model = new TokenModel(grantType, {allowExtendedTokenAttributes: this.allowExtendedTokenAttributes});
        var tokenType = this.getTokenType(model);
        return this.updateSuccessResponse(response, tokenType);
    } catch (e) {
        if (!(e instanceof OAuthError)) {
            e = new ServerError(e);
        }

        this.updateErrorResponse(response, e);

        throw e;
    }


  //   this.updateSuccessResponse(response, tokenType);
  // return Promise.bind(this)
  //   .then(function() {
  //     return this.getClient(request, response);
  //   })
  //   .then(function(client) {
  //     return this.handleGrantType(request, client);
  //   })
  //   .tap(function(data) {
  //       throw new Error('got grant type')
  //     var model = new TokenModel(data, {allowExtendedTokenAttributes: this.allowExtendedTokenAttributes});
  //     var tokenType = this.getTokenType(model);
  //
  //     this.updateSuccessResponse(response, tokenType);
  //   }).catch(function(e) {
  //     if (!(e instanceof OAuthError)) {
  //       e = new ServerError(e);
  //     }
  //
  //     this.updateErrorResponse(response, e);
  //
  //     throw e;
  //   });
};

/**
 * Get the client from the model.
 */

TokenHandler.prototype.getClient = async function(request, response) {
    const body = await this.readRequestBody(request)
  var credentials = await this.getClientCredentials(request);
  var grantType = body.grant_type;

  if (!credentials.clientId) {
    throw new InvalidRequestError('Missing parameter: `client_id`');
  }

  if (this.isClientAuthenticationRequired(grantType) && !credentials.clientSecret) {
    throw new InvalidRequestError('Missing parameter: `client_secret`');
  }

  if (!is.vschar(credentials.clientId)) {
    throw new InvalidRequestError('Invalid parameter: `client_id`');
  }

  if (credentials.clientSecret && !is.vschar(credentials.clientSecret)) {
    throw new InvalidRequestError('Invalid parameter: `client_secret`');
  }

  return promisify(this.model.getClient, 2).call(this.model, credentials.clientId, credentials.clientSecret)
    .then(function(client) {
      if (!client) {
        throw new InvalidClientError('Invalid client: client is invalid');
      }

      if (!client.grants) {
        throw new ServerError('Server error: missing client `grants`');
      }

      if (!(client.grants instanceof Array)) {
        throw new ServerError('Server error: `grants` must be an array');
      }

      return client;
    })
    .catch(function(e) {
      // Include the "WWW-Authenticate" response header field if the client
      // attempted to authenticate via the "Authorization" request header.
      //
      // @see https://tools.ietf.org/html/rfc6749#section-5.2.
      if ((e instanceof InvalidClientError) && request.get('authorization')) {
        response.set('WWW-Authenticate', 'Basic realm="Service"');

        throw new InvalidClientError(e, { code: 401 });
      }

      throw e;
    });
};

TokenHandler.prototype.getClientCredentialsFromHeader = function(request) {
    let auth_val = request.headers.get('Authorization')
    if(!auth_val) return null
    let auth_val_split = auth_val.split(' ')
    if(auth_val_split[0] !== 'Basic') return null
    let decoded = atob(auth_val_split[1]).split(':')
    return {name: decoded[0], pass: decoded[1]}
}

/**
 * Get client credentials.
 *
 * The client credentials may be sent using the HTTP Basic authentication scheme or, alternatively,
 * the `client_id` and `client_secret` can be embedded in the body.
 *
 * @see https://tools.ietf.org/html/rfc6749#section-2.3.1
 */

TokenHandler.prototype.getClientCredentials = async function(request) {
    const body = await this.readRequestBody(request)
  var credentials = this.getClientCredentialsFromHeader(request);
  var grantType = body.grant_type;

  if (credentials) {
    return { clientId: credentials.name, clientSecret: credentials.pass };
  }

  if (body.client_id && body.client_secret) {
    return { clientId: body.client_id, clientSecret: body.client_secret };
  }

  if (!this.isClientAuthenticationRequired(grantType)) {
    if(body.client_id) {
      return { clientId: body.client_id };
    }
  }

  throw new InvalidClientError('Invalid client: cannot retrieve client credentials');
};

/**
 * Handle grant type.
 */

TokenHandler.prototype.handleGrantType = async function(request, client) {
    const body = await this.readRequestBody(request)
  var grantType = body.grant_type;

  if (!grantType) {
    throw new InvalidRequestError('Missing parameter: `grant_type`');
  }

  if (!is.nchar(grantType) && !is.uri(grantType)) {
    throw new InvalidRequestError('Invalid parameter: `grant_type`');
  }

  if (!(grantType in this.grantTypes)) {
    throw new UnsupportedGrantTypeError('Unsupported grant type: `grant_type` is invalid');
  }

  if (!client.grants.includes(grantType)) {
    throw new UnauthorizedClientError('Unauthorized client: `grant_type` is invalid');
  }

  var accessTokenLifetime = this.getAccessTokenLifetime(client);
  var refreshTokenLifetime = this.getRefreshTokenLifetime(client);
  var Type = this.grantTypes[grantType];

  var options = {
    accessTokenLifetime: accessTokenLifetime,
    model: this.model,
    refreshTokenLifetime: refreshTokenLifetime,
    alwaysIssueNewRefreshToken: this.alwaysIssueNewRefreshToken
  };

  return new Type(options)
    .handle(request, client);
};

/**
 * Get access token lifetime.
 */

TokenHandler.prototype.getAccessTokenLifetime = function(client) {
  return client.accessTokenLifetime || this.accessTokenLifetime;
};

/**
 * Get refresh token lifetime.
 */

TokenHandler.prototype.getRefreshTokenLifetime = function(client) {
  return client.refreshTokenLifetime || this.refreshTokenLifetime;
};

/**
 * Get token type.
 */

TokenHandler.prototype.getTokenType = function(model) {
  return new BearerTokenType(model.accessToken, model.accessTokenLifetime, model.refreshToken, model.scope, model.customAttributes);
};

/**
 * Update response when a token is generated.
 */

TokenHandler.prototype.updateSuccessResponse = function(response, tokenType) {
    response = new Response(JSON.stringify(tokenType), response)
    // response.body = tokenType.valueOf();

    response.headers.set('Cache-Control', 'no-store');
    response.headers.set('Pragma', 'no-cache');
    response.headers.set('Content-type', 'application/json')
    return response
};

/**
 * Update response when an error is thrown.
 */

TokenHandler.prototype.updateErrorResponse = function(response, error) {
  const body = {
    error: error.name,
    error_description: error.message
  };
  response = new Response(body,{status: error.code})
};

/**
 * Given a grant type, check if client authentication is required
 */
TokenHandler.prototype.isClientAuthenticationRequired = function(grantType) {
  if (Object.keys(this.requireClientAuthentication).length > 0) {
    return (typeof this.requireClientAuthentication[grantType] !== 'undefined') ? this.requireClientAuthentication[grantType] : true;
  } else {
    return true;
  }
};

/**
 * Export constructor.
 */

module.exports = TokenHandler;
