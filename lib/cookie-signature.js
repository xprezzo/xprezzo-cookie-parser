/**
 * Module dependencies.
 */

const crypto = require('crypto')

/**
 * Sign the given `val` with `secret`.
 *
 * @param {String} val
 * @param {String} secret
 * @return {String}
 * @api private
 */

exports.sign = (val, secret) => {
  if (typeof val !== 'string') throw new TypeError('Cookie value must be provided as a string.')
  if (typeof secret !== 'string') throw new TypeError('Secret string must be provided.')
  return val + '.' + crypto
    .createHmac('sha256', secret)
    .update(val)
    .digest('base64')
    .replace(/=+$/, '')
}

/**
 * Unsign and decode the given `val` with `secret`,
 * returning `false` if the signature is invalid.
 *
 * @param {String} val
 * @param {String} secret
 * @return {String|Boolean}
 * @api private
 */

exports.unsign = (val, secret) => {
  if (typeof val !== 'string') throw new TypeError('Signed cookie string must be provided.')
  if (typeof secret !== 'string') throw new TypeError('Secret string must be provided.')
  var str = val.slice(0, val.lastIndexOf('.'))
  var mac = exports.sign(str, secret)
  var macBuffer = Buffer.from(mac)
  var valBuffer = Buffer.alloc(macBuffer.length)

  valBuffer.write(val)
  return crypto.timingSafeEqual(macBuffer, valBuffer) ? str : false
}
