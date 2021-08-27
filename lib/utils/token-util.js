'use strict';

/**
 * Module dependencies.
 */

const crypto = require('crypto-browserify')
// const uuid = require("uuid");


/**
 * Export `TokenUtil`.
 */

module.exports = {

  /**
   * Generate random token.
   */

    generateRandomToken: function() {
      // return uuid.v4();
        let buffer = crypto.randomBytes(256)
        return crypto.createHash('sha256')
          .update(buffer)
          .digest('hex');
    }

};
