'use strict'

/**
 * Module variables.
 * @private
 */

const decode = decodeURIComponent
const encode = encodeURIComponent
const pairSplitRegExp = /;\s*/

/**
 * RegExp to match field-content in RFC 7230 sec 3.2
 *
 * field-content = field-vchar [ 1*( SP / HTAB ) field-vchar ]
 * field-vchar   = VCHAR / obs-text
 * obs-text      = %x80-FF
 */

const fieldContentRegExp = /^[\u0009\u0020-\u007e\u0080-\u00ff]+$/

/**
 * Try decoding a string using a decoding function.
 *
 * @param {string} str
 * @param {function} decode
 * @private
 */
const tryDecode = (str, decode) => {
  try {
    return decode(str)
  } catch (e) {
    return str
  }
}

/**
 * Parse a cookie header.
 *
 * Parse the given cookie header string into an object
 * The object has the various cookies as keys(names) => values
 *
 * @param {string} str
 * @param {object} [options]
 * @return {object}
 * @public
 */
exports.parse = (str, options) => {
  if (typeof str !== 'string') {
    throw new TypeError('argument str must be a string')
  }

  const obj = {}
  const opt = options || {}
  const pairs = str.split(pairSplitRegExp)
  const dec = opt.decode || decode

  for (let i = 0; i < pairs.length; i++) {
    const pair = pairs[i]
    let eqIdx = pair.indexOf('=')

    // skip things that don't look like key=value
    if (eqIdx < 0) {
      continue
    }

    const key = pair.substr(0, eqIdx).trim()
    let val = pair.substr(++eqIdx, pair.length).trim()

    // quoted values
    if (val[0] === '"') {
      val = val.slice(1, -1)
    }

    // only assign once
    if (undefined === obj[key]) {
      obj[key] = tryDecode(val, dec)
    }
  }

  return obj
}
/**
 * Serialize data into a cookie header.
 *
 * Serialize the a name value pair into a cookie string suitable for
 * http headers. An optional options object specified cookie parameters.
 *
 * serialize('foo', 'bar', { httpOnly: true })
 *   => "foo=bar; httpOnly"
 *
 * @param {string} name
 * @param {string} val
 * @param {object} [options]
 * @return {string}
 * @public
 */
exports.serialize = (name, val, options) => {
  const opt = options || {}
  const enc = opt.encode || encode

  if (typeof enc !== 'function') {
    throw new TypeError('option encode is invalid')
  }

  if (!fieldContentRegExp.test(name)) {
    throw new TypeError('argument name is invalid')
  }

  const value = enc(val)

  if (value && !fieldContentRegExp.test(value)) {
    throw new TypeError('argument val is invalid')
  }

  let str = name + '=' + value

  if (opt.maxAge != null) {
    const maxAge = opt.maxAge - 0

    if (isNaN(maxAge) || !isFinite(maxAge)) {
      throw new TypeError('option maxAge is invalid')
    }

    str += '; Max-Age=' + Math.floor(maxAge)
  }

  if (opt.domain) {
    if (!fieldContentRegExp.test(opt.domain)) {
      throw new TypeError('option domain is invalid')
    }

    str += '; Domain=' + opt.domain
  }

  if (opt.path) {
    if (!fieldContentRegExp.test(opt.path)) {
      throw new TypeError('option path is invalid')
    }

    str += '; Path=' + opt.path
  }

  if (opt.expires) {
    if (typeof opt.expires.toUTCString !== 'function') {
      throw new TypeError('option expires is invalid')
    }

    str += '; Expires=' + opt.expires.toUTCString()
  }

  if (opt.httpOnly) {
    str += '; HttpOnly'
  }

  if (opt.secure) {
    str += '; Secure'
  }

  if (opt.sameSite) {
    const sameSite = typeof opt.sameSite === 'string'
      ? opt.sameSite.toLowerCase() : opt.sameSite

    switch (sameSite) {
      case true:
        str += '; SameSite=Strict'
        break
      case 'lax':
        str += '; SameSite=Lax'
        break
      case 'strict':
        str += '; SameSite=Strict'
        break
      case 'none':
        str += '; SameSite=None'
        break
      default:
        throw new TypeError('option sameSite is invalid')
    }
  }

  return str
}
