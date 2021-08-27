'use strict';

/**
 * Module dependencies.
 */

var InvalidArgumentError = require('../errors/invalid-argument-error');

/**
 * Constructor.
 */

function CodeResponseType(code) {
  if (!code) {
    throw new InvalidArgumentError('Missing parameter: `code`');
  }

  this.code = code;
}

/**
 * Build redirect uri.
 */

CodeResponseType.prototype.buildRedirectUri = function(redirectUri) {
  if (!redirectUri) {
    throw new InvalidArgumentError('Missing parameter: `redirectUri`');
  }

  let uri = new URL(redirectUri)

  uri.searchParams.set('code', this.code)

  return uri;
};

/**
 * Export constructor.
 */

module.exports = CodeResponseType;
