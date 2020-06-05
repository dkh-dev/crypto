'use strict'

const crypto = require('crypto')

const { callback } = require('./utils/promisify')


/**
 * @private
 */
const randomBytesAsync = callback(crypto.randomBytes)

const randomBytes = size => randomBytesAsync(size)

module.exports = randomBytes
