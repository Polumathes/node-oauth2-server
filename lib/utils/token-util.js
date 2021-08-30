'use strict';

/**
 * Module dependencies.
 */

const crypto = require('crypto-browserify')


/**
 * Export `TokenUtil`.
 */

module.exports = {

  /**
   * Generate random token.
   */

    generateRandomToken: function() {
        let buffer = crypto.randomBytes(256)
        return crypto.createHash('sha256')
          .update(buffer)
          .digest('hex');
    }

};
