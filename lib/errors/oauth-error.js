'use strict';

/**
 * Module dependencies.
 */
var util = require('util');
var statuses = require('statuses');
/**
 * Constructor.
 */

function OAuthError(messageOrError, properties) {
  var message = messageOrError instanceof Error ? messageOrError.message : messageOrError;
  var error = messageOrError instanceof Error ? messageOrError : null;
  if(!properties || typeof properties !== 'object') { properties = {}; }
  if(!('code' in properties)) { properties.code = 500; }

  if (error) {
    properties.inner = error;
  }
  if (!message || message === '') {
    message = statuses[properties.code];
  }
  this.code = this.status = this.statusCode = properties.code;
  this.message = message;
  for (var key in properties) {
    if (key !== 'code') {
      this[key] = properties[key];
    }
  }
  Error.captureStackTrace(this, OAuthError);
}

util.inherits(OAuthError, Error);

/**
 * Export constructor.
 */

module.exports = OAuthError;
