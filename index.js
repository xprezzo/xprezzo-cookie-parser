/*!
 * xprezzo-cookie-parser
 * Copyright(c) 2022 Cloudgen Wong <cloudgen.wong@gmail.com>
 * MIT Licensed
 */

'use strict'

/**
 * Module dependencies.
 * @private
 */

const cookie = require('./lib/cookie')
const signature = require('./lib/cookie-signature')

/**
 * Parse JSON cookie string.
 *
 * @param {String} str
 * @return {Object} Parsed object or undefined if not json cookie
 * @public
 */

function JSONCookie (str) {
  if (typeof str !== 'string' || str.substr(0, 2) !== 'j:') {
    return undefined
  }

  try {
    return JSON.parse(str.slice(2))
  } catch (err) {
    return undefined
  }
}

/**
 * Parse JSON cookies.
 *
 * @param {Object} obj
 * @return {Object}
 * @public
 */

const JSONCookies = (obj) => {
  const cookies = Object.keys(obj)
  let key
  let val

  for (let i = 0; i < cookies.length; i++) {
    key = cookies[i]
    val = JSONCookie(obj[key])

    if (val) {
      obj[key] = val
    }
  }

  return obj
}

/**
 * Parse signed cookies, returning an object containing the decoded key/value
 * pairs, while removing the signed key from obj.
 *
 * @param {Object} obj
 * @param {string|array} secret
 * @return {Object}
 * @public
 */
const signedCookies = (obj, secret) => {
  const cookies = Object.keys(obj)
  let dec
  let key
  const ret = Object.create(null)
  let val

  for (let i = 0; i < cookies.length; i++) {
    key = cookies[i]
    val = obj[key]
    dec = signedCookie(val, secret)

    if (val !== dec) {
      ret[key] = dec
      delete obj[key]
    }
  }

  return ret
}

/**
 * Parse a signed cookie string, return the decoded value.
 *
 * @param {String} str signed cookie string
 * @param {string|array} secret
 * @return {String} decoded value
 * @public
 */
const signedCookie = (str, secret) => {
  if (typeof str !== 'string') {
    return undefined
  }

  if (str.substr(0, 2) !== 's:') {
    return str
  }

  const secrets = !secret || Array.isArray(secret) ? (secret || []) : [secret]

  for (let i = 0; i < secrets.length; i++) {
    const val = signature.unsign(str.slice(2), secrets[i])

    if (val !== false) {
      return val
    }
  }
  return false
}

/**
* Parse Cookie header and populate `req.cookies`
* with an object keyed by the cookie names.
*
* @param {string|array} [secret] A string (or array of strings) representing cookie signing secret(s).
* @param {Object} [options]
* @return {Function}
* @public
*/
module.exports = (secret, options) => {
  const secrets = !secret || Array.isArray(secret)
    ? (secret || [])
    : [secret]

  return (req, res, next) => {
    if (req.cookies) {
      return next()
    }

    const cookies = req.headers.cookie

    req.secret = secrets[0]
    req.cookies = Object.create(null)
    req.signedCookies = Object.create(null)

    // no cookies
    if (!cookies) {
      return next()
    }

    req.cookies = cookie.parse(cookies, options)

    // parse signed cookies
    if (secrets.length !== 0) {
      req.signedCookies = signedCookies(req.cookies, secrets)
      req.signedCookies = JSONCookies(req.signedCookies)
    }

    // parse JSON cookies
    req.cookies = JSONCookies(req.cookies)

    next()
  }
}
module.exports.JSONCookie = JSONCookie
module.exports.JSONCookies = JSONCookies
module.exports.signedCookie = signedCookie
module.exports.signedCookies = signedCookies
module.exports.cookie = cookie
module.exports.cookieSignature = signature
