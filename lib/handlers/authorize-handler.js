'use strict';

/**
 * Module dependencies.
 */

var AccessDeniedError = require('../errors/access-denied-error');
var AuthenticateHandler = require('../handlers/authenticate-handler');
var InvalidArgumentError = require('../errors/invalid-argument-error');
var InvalidClientError = require('../errors/invalid-client-error');
var InvalidRequestError = require('../errors/invalid-request-error');
var InvalidScopeError = require('../errors/invalid-scope-error');
var UnsupportedResponseTypeError = require('../errors/unsupported-response-type-error');
var OAuthError = require('../errors/oauth-error');
var Promise = require('bluebird');
var promisify = require('promisify-any').use(Promise);
// var Request = require('../request');
// var Response = require('../response');
var ServerError = require('../errors/server-error');
var UnauthorizedClientError = require('../errors/unauthorized-client-error');
var is = require('../validator/is');
var tokenUtil = require('../utils/token-util');

/**
 * Response types.
 */

var responseTypes = {
  code: require('../response-types/code-response-type'),
  //token: require('../response-types/token-response-type')
};

/**
 * Constructor.
 */

function AuthorizeHandler(options) {
  options = options || {};

  if (options.authenticateHandler && !options.authenticateHandler.handle) {
    throw new InvalidArgumentError('Invalid argument: authenticateHandler does not implement `handle()`');
  }

  if (!options.authorizationCodeLifetime) {
    throw new InvalidArgumentError('Missing parameter: `authorizationCodeLifetime`');
  }

  if (!options.model) {
    throw new InvalidArgumentError('Missing parameter: `model`');
  }

  if (!options.model.getClient) {
    throw new InvalidArgumentError('Invalid argument: model does not implement `getClient()`');
  }

  if (!options.model.saveAuthorizationCode) {
    throw new InvalidArgumentError('Invalid argument: model does not implement `saveAuthorizationCode()`');
  }

  this.allowEmptyState = options.allowEmptyState;
  this.authenticateHandler = options.authenticateHandler || new AuthenticateHandler(options);
  this.authorizationCodeLifetime = options.authorizationCodeLifetime;
  this.model = options.model;
}

/**
 * Authorize Handler.
 */

AuthorizeHandler.prototype.handle = async function(request, response) {
  if (!(request instanceof Request)) {
    throw new InvalidArgumentError('Invalid argument: `request` must be an instance of Request');
  }

  if (!(response instanceof Response)) {
    throw new InvalidArgumentError('Invalid argument: `response` must be an instance of Response');
  }

  const query = getRequestParams(request.url)
  if ('false' === query.allowed) {
    return Promise.reject(new AccessDeniedError('Access denied: user denied access to application'));
  }

  var fns = [
    this.getAuthorizationCodeLifetime(),
    await this.getClient(request),
    this.getUser(request, response)
  ];

  return Promise.all(fns)
    .bind(this)
    .spread(async function(expiresAt, client, user) {
      var uri = await this.getRedirectUri(request, client);
      var scope;
      var state;
      var ResponseType;

      return Promise.bind(this)
        .then(async function() {
          var requestedScope = await this.getScope(request);

          return this.validateScope(user, client, requestedScope);
        })
        .then(function(validScope) {
          scope = validScope;

          return this.generateAuthorizationCode(client, user, scope);
        })
        .then(async function(authorizationCode) {
          state = await this.getState(request);
          ResponseType = await this.getResponseType(request);

          return this.saveAuthorizationCode(authorizationCode, expiresAt, scope, client, uri, user);
        })
        .then(function(code) {
          var responseType = new ResponseType(code.authorizationCode);
          var redirectUri = this.buildSuccessRedirectUri(uri, responseType);

          this.updateResponse(response, redirectUri, state);

          return code;
        })
        .catch(function(e) {
          if (!(e instanceof OAuthError)) {
            e = new ServerError(e);
          }
          var redirectUri = this.buildErrorRedirectUri(uri, e);

          this.updateResponse(response, redirectUri, state);

          throw e;
        });
    });
};

AuthorizeHandler.prototype.readRequestBody = async (request) => {
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

AuthorizeHandler.prototype.getRequestParams = (url) => {
    const { searchParams } = new URL(url)
    const search_params = {}
    for (const key of searchParams.keys()) {
        search_params[key] = searchParams.get(key)
    }
    return search_params
}

/**
 * Generate authorization code.
 */

AuthorizeHandler.prototype.generateAuthorizationCode = function(client, user, scope) {
  if (this.model.generateAuthorizationCode) {
    return promisify(this.model.generateAuthorizationCode, 3).call(this.model, client, user, scope);
  }
  return tokenUtil.generateRandomToken();
};

/**
 * Get authorization code lifetime.
 */

AuthorizeHandler.prototype.getAuthorizationCodeLifetime = function() {
  var expires = new Date();

  expires.setSeconds(expires.getSeconds() + this.authorizationCodeLifetime);
  return expires;
};

/**
 * Get the client from the model.
 */

AuthorizeHandler.prototype.getClient = async function(request) {
    const query = this.getRequestParams(request.url)
    const body = await this.readRequestBody(request)
  var clientId =body.client_id || query.client_id;

  if (!clientId) {
    throw new InvalidRequestError('Missing parameter: `client_id`');
  }

  if (!is.vschar(clientId)) {
    throw new InvalidRequestError('Invalid parameter: `client_id`');
  }

  var redirectUri = body.redirect_uri || query.redirect_uri;

  if (redirectUri && !is.uri(redirectUri)) {
    throw new InvalidRequestError('Invalid request: `redirect_uri` is not a valid URI');
  }
  return promisify(this.model.getClient, 2).call(this.model, clientId, null)
    .then(function(client) {
      if (!client) {
        throw new InvalidClientError('Invalid client: client credentials are invalid');
      }

      if (!client.grants) {
        throw new InvalidClientError('Invalid client: missing client `grants`');
      }

      if (!client.grants.includes('authorization_code')) {
        throw new UnauthorizedClientError('Unauthorized client: `grant_type` is invalid');
      }

      if (!client.redirectUris || 0 === client.redirectUris.length) {
        throw new InvalidClientError('Invalid client: missing client `redirectUri`');
      }

      if (redirectUri && !client.redirectUris.includes(redirectUri)) {
        throw new InvalidClientError('Invalid client: `redirect_uri` does not match client value');
      }
      return client;
    });
};

/**
 * Validate requested scope.
 */
AuthorizeHandler.prototype.validateScope = function(user, client, scope) {
  if (this.model.validateScope) {
    return promisify(this.model.validateScope, 3).call(this.model, user, client, scope)
      .then(function (scope) {
        if (!scope) {
          throw new InvalidScopeError('Invalid scope: Requested scope is invalid');
        }

        return scope;
      });
  } else {
    return Promise.resolve(scope);
  }
};

/**
 * Get scope from the request.
 */

AuthorizeHandler.prototype.getScope = async function(request) {
    const query = this.getRequestParams(request.url)
    const body = await this.readRequestBody(request)
  var scope = body.scope || query.scope;

  if (!is.nqschar(scope)) {
    throw new InvalidScopeError('Invalid parameter: `scope`');
  }

  return scope;
};

/**
 * Get state from the request.
 */

AuthorizeHandler.prototype.getState = async function(request) {
    const query = this.getRequestParams(request.url)
    const body = await this.readRequestBody(request)
  var state = body.state || query.state;

  if (!this.allowEmptyState && !state) {
    throw new InvalidRequestError('Missing parameter: `state`');
  }

  if (!is.vschar(state)) {
    throw new InvalidRequestError('Invalid parameter: `state`');
  }

  return state;
};

/**
 * Get user by calling the authenticate middleware.
 */

AuthorizeHandler.prototype.getUser = function(request, response) {
  if (this.authenticateHandler instanceof AuthenticateHandler) {
    return this.authenticateHandler.handle(request, response).get('user');
  }
  return promisify(this.authenticateHandler.handle, 2)(request, response).then(function(user) {
    if (!user) {
      throw new ServerError('Server error: `handle()` did not return a `user` object');
    }

    return user;
  });
};

/**
 * Get redirect URI.
 */

AuthorizeHandler.prototype.getRedirectUri = async function(request, client) {
    const query = this.getRequestParams(request.url)
    const body = await this.readRequestBody(request)
  return body.redirect_uri || query.redirect_uri || client.redirectUris[0];
};

/**
 * Save authorization code.
 */

AuthorizeHandler.prototype.saveAuthorizationCode = function(authorizationCode, expiresAt, scope, client, redirectUri, user) {
  var code = {
    authorizationCode: authorizationCode,
    expiresAt: expiresAt,
    redirectUri: redirectUri,
    scope: scope
  };
  return promisify(this.model.saveAuthorizationCode, 3).call(this.model, code, client, user);
};

/**
 * Get response type.
 */

AuthorizeHandler.prototype.getResponseType = async function(request) {
    const query = this.getRequestParams(request.url)
    const body = await this.readRequestBody(request)
  var responseType = body.response_type || query.response_type;

  if (!responseType) {
    throw new InvalidRequestError('Missing parameter: `response_type`');
  }

  if (!(responseType in responseTypes)) {
    throw new UnsupportedResponseTypeError('Unsupported response type: `response_type` is not supported');
  }

  return responseTypes[responseType];
};

/**
 * Build a successful response that redirects the user-agent to the client-provided url.
 */

AuthorizeHandler.prototype.buildSuccessRedirectUri = function(redirectUri, responseType) {
  return responseType.buildRedirectUri(redirectUri);
};

/**
 * Build an error response that redirects the user-agent to the client-provided url.
 */

AuthorizeHandler.prototype.buildErrorRedirectUri = function(redirectUri, error) {
  var uri = new URL(redirectUri);

    uri.searchParams.append('error', error.name);

  if (error.message) {
      uri.searchParams.append('error_description', error.message);
  }

  return uri;
};

/**
 * Update response with the redirect uri and the state parameter, if available.
 */

AuthorizeHandler.prototype.updateResponse = function(response, redirectUri, state) {

  if (state) {
    redirectUri.searchParams.append(state, state);
  }

  response.redirect(redirectUri.toString());
};

/**
 * Export constructor.
 */

module.exports = AuthorizeHandler;
