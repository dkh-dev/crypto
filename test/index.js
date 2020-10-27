'use strict'

/* eslint-disable max-statements */

const { readFileSync, createReadStream } = require('fs')
const { createPrivateKey, createPublicKey } = require('crypto')

const test = require('tape')
const helper = require('@dkh-dev/tape-helper')

const { aes256, box, hash, hmac, scrypt, randomBytes } = require('..')


const DATA = 'data'
const PASSWORD = 'secret'
const AAD = 'aad'
const SHA256_HASH = 'Om6weQ85rIfJTzhWst0sXREOaBFgImGpqSPTuyOtyLc='
const SHA256_HMAC = 'GywWt1vSqHDBFBU8zaW8/KYzFLxyL6Fg1pDeEzzLuds='
const LARGE_DATA = '0123456789'.repeat(1e6)
const LARGE_PASSWORD = '9876543210'.repeat(1e6)
const WRONG_DATA = DATA.toUpperCase()
const WRONG_PASSWORD = PASSWORD.toUpperCase()
const WRONG_AAD = 'invalid-aad'
// image from:
// https://www.flaticon.com/free-icon/kitty_763789?term=cat&page=1&position=31
const FILE = `${ __dirname }/kitty.png`
const FILE_SHA256_HASH = Buffer.from(
  'AA9B54BF0670991E68939493E1C7F6EC85788D1DEABDF1A35890E8A32157DDF0',
  'hex',
)
const KEY_PRIVATE = `${ __dirname }/key.pem`
const KEY_PUBLIC = `${ __dirname }/key.pub`


helper(test)

test('box', t => {
  const privateKey = createPrivateKey(readFileSync(KEY_PRIVATE))
  const publicKey = createPublicKey(readFileSync(KEY_PUBLIC))

  t.plan(6)

  t.eq(async () => {
    const encrypted = await box.seal(publicKey, DATA)
    const decrypted = await box.open(privateKey, encrypted)

    return decrypted.toString()
  }, DATA, 'public encrypt private decrypt')

  t.eq(async () => {
    const encrypted = await box.seal(privateKey, DATA)
    const decrypted = await box.open(privateKey, encrypted)

    return decrypted.toString()
  }, DATA, 'seal accepts private key as well')

  t.throws(() => (
    box.open(publicKey, DATA)
  ), 'box can only opened using private key')

  t.eq(async () => {
    const encrypted = await box.seal(publicKey, LARGE_DATA)
    const decrypted = await box.open(privateKey, encrypted)

    return decrypted.toString()
  }, LARGE_DATA, 'large box data')


  t.eq(async () => {
    const encrypted = await box.seal(publicKey, DATA, AAD)
    const decrypted = await box.open(privateKey, encrypted, AAD)

    return decrypted.toString()
  }, DATA, 'seal a box with aad')

  t.throws(async () => {
    const encrypted = await box.seal(publicKey, DATA, AAD)

    return box.open(privateKey, encrypted, WRONG_AAD)
  }, 'invalid box aad')
})

test('secret box', t => {
  t.plan(8)

  t.eq(async () => {
    const encrypted = await aes256.encrypt(PASSWORD, DATA)
    const decrypted = await aes256.decrypt(PASSWORD, encrypted)

    return decrypted.toString()
  }, DATA, 'the decrypted string equals to the input data')

  t.resolves(aes256.encrypt(PASSWORD, LARGE_DATA), 'large data')
  t.resolves(aes256.encrypt(LARGE_PASSWORD, DATA), 'large password')
  t.rejects(aes256.encrypt(PASSWORD), 'data must not be empty')
  t.rejects(aes256.encrypt(null, DATA), 'password must not be empty')

  t.eq(async () => {
    const encrypted = await aes256.encrypt(LARGE_PASSWORD, LARGE_DATA)
    const decrypted = await aes256.decrypt(LARGE_PASSWORD, encrypted)

    return decrypted.toString()
  }, LARGE_DATA, 'decrypted large data')

  t.eq(async () => {
    const encrypted = await aes256.encrypt(PASSWORD, DATA, AAD)
    const decrypted = await aes256.decrypt(PASSWORD, encrypted, AAD)

    return decrypted.toString()
  }, DATA, 'encryption and decryption with aad')

  t.throws(async () => {
    const encrypted = await aes256.encrypt(PASSWORD, DATA)
    const decrypted = await aes256.decrypt(PASSWORD, encrypted, WRONG_AAD)

    return decrypted.toString()
  }, 'invalid aad')
})

test('aes256', t => {
  t.plan(9)

  t.eq(async () => {
    const encrypted = await aes256.encrypt(PASSWORD, DATA)
    const decrypted = await aes256.decrypt(PASSWORD, encrypted)

    return decrypted.toString()
  }, DATA, 'the decrypted string equals to the input data')

  t.resolves(aes256.encrypt(PASSWORD, LARGE_DATA), 'large data')
  t.resolves(aes256.encrypt(LARGE_PASSWORD, DATA), 'large password')
  t.rejects(aes256.encrypt(PASSWORD), 'data must not be empty')
  t.rejects(aes256.encrypt(null, DATA), 'password must not be empty')

  t.eq(async () => {
    const encrypted = await aes256.encrypt(LARGE_PASSWORD, LARGE_DATA)
    const decrypted = await aes256.decrypt(LARGE_PASSWORD, encrypted)

    return decrypted.toString()
  }, LARGE_DATA, 'decrypted large data')

  t.eq(async () => {
    const encrypted = await aes256.encrypt(PASSWORD, createReadStream(FILE))

    return aes256.decrypt(PASSWORD, encrypted)
  }, readFileSync(FILE), 'encryption accepts stream')

  t.eq(async () => {
    const encrypted = await aes256.encrypt(PASSWORD, DATA, AAD)
    const decrypted = await aes256.decrypt(PASSWORD, encrypted, AAD)

    return decrypted.toString()
  }, DATA, 'encryption and decryption with aad')

  t.throws(async () => {
    const encrypted = await aes256.encrypt(PASSWORD, DATA)
    const decrypted = await aes256.decrypt(PASSWORD, encrypted, WRONG_AAD)

    return decrypted.toString()
  }, 'invalid aad')
})

test('scrypt.hash', t => {
  t.plan(12)

  t.doesNotThrow(async () => {
    const buffer = await scrypt.hash(PASSWORD, DATA)

    t.eq(scrypt.verify(PASSWORD, DATA, buffer), true, 'authenticated data')
    t.eq(scrypt.verify(PASSWORD, WRONG_DATA, buffer), false, 'invalid data')
    t.eq(scrypt.verify(WRONG_PASSWORD, DATA, buffer), false, 'invalid password')
  })

  t.resolves(scrypt.hash(PASSWORD, LARGE_DATA), 'scrypt hash large data')
  t.resolves(scrypt.hash(LARGE_PASSWORD, DATA), 'scrypt hash large password')
  t.rejects(scrypt.hash(PASSWORD), 'data must not be empty')
  t.rejects(scrypt.hash(null, DATA), 'password must not be empty')
  t.rejects(scrypt.hash(PASSWORD, DATA, { r: 256 }), 'invalid options.r')
  t.rejects(scrypt.hash(PASSWORD, DATA, { p: 256 }), 'invalid options.p')

  t.eq(async () => {
    const buffer = await scrypt.hash(LARGE_PASSWORD, LARGE_DATA)

    return scrypt.verify(LARGE_PASSWORD, LARGE_DATA, buffer)
  }, true, 'authenticated data')

  t.eq(async () => {
    const options = Object.freeze({ N: 2 ** 12, r: 16, p: 2 })
    const buffer = await scrypt.hash(PASSWORD, DATA, options)

    return scrypt.verify(PASSWORD, DATA, buffer)
  }, true, 'user-defined scrypt options')
})

test('scrypt.hashiv', t => {
  t.plan(1)

  t.eq(async () => {
    const ivSize = { logN: 2, r: 4, p: 4 }
    const saltSize = 64

    const iv = scrypt.subtle.deriveIv({ N: 2 ** 11, r: 15, p: 3 }, ivSize)
    const salt = await randomBytes(saltSize)
    const buffer = await scrypt.subtle.hashiv(PASSWORD, iv, salt, DATA)

    return scrypt.verify(PASSWORD, DATA, buffer)
  }, true, 'scrypt hash includes sufficient metadata for verification')
})

test('scrypt.derive', t => {
  t.plan(4)

  t.doesNotThrow(async () => {
    const key = await scrypt.subtle.derive(DATA, PASSWORD, 32)
    const same = await scrypt.subtle.derive(DATA, PASSWORD, 32)
    const different = await scrypt.subtle.derive(DATA, PASSWORD, 32, { N: 4 })

    t.eq(key.length, 32, 'scrypt derived key size equals to the defined size')
    t.eq(key, same, 'same input produces same hash')

    t.ne(key, different, 'different input')
  })
})

test('randomBytes', t => {
  t.plan(3)

  t.ne(randomBytes(100), randomBytes(100), 'should not be the same')
  t.eq(async () => {
    const buffer = await randomBytes(100)

    return buffer.length
  }, 100, 'buffer size equals to the specified size')

  t.rejects(randomBytes('invalid'), 'size must be of type number')
})

test('hash.sha256', t => {
  t.plan(9)

  t.doesNotThrow(async () => {
    const buffer = await hash.sha256(DATA)

    t.eq(buffer.length * 8, 256, 'sha256 hash size is 256 bits')
    t.eq(buffer.toString('base64'), SHA256_HASH, 'same hash')

    t.eq(await hash.sha256(DATA), buffer, 'same hash for same data')
    t.ne(await hash.sha256(WRONG_DATA), buffer, 'invalid data')
  })

  t.resolves(hash.sha256(LARGE_DATA), 'hash large data')

  t.doesNotThrow(async () => {
    const buffer = await hash.sha256(createReadStream(FILE))

    t.eq(buffer, FILE_SHA256_HASH)
    t.eq(buffer, await hash.sha256(readFileSync(FILE)))
  })
})

test('hmac.sha256', t => {
  t.plan(12)

  t.doesNotThrow(async () => {
    const buffer = await hmac.sha256(PASSWORD, DATA)

    t.eq(
      buffer.length * 8, 256,
      'hmac sha256 size is equal to sha256 hash size of 256 bits',
    )
    t.eq(
      buffer.toString('base64'),
      SHA256_HMAC,
      'same hmac',
    )

    t.eq(
      hmac.sha256(PASSWORD, DATA),
      buffer,
      'same hmac for same data and password',
    )
    t.ne(hmac.sha256(PASSWORD, WRONG_DATA), buffer, 'invalid data')
    t.ne(hmac.sha256(WRONG_PASSWORD, DATA), buffer, 'invalid passwords')
  })

  t.resolves(hmac.sha256(PASSWORD, LARGE_DATA), 'large data')
  t.resolves(hmac.sha256(LARGE_PASSWORD, DATA), 'large password')
  t.throws(() => hmac.sha256(PASSWORD), 'data must not be empty')
  t.throws(() => hmac.sha256(null, DATA), 'password must not be empty')

  t.eq(
    hmac.sha256(PASSWORD, createReadStream(FILE)),
    hmac.sha256(PASSWORD, readFileSync(FILE)),
    'hmac sha256 from file stream',
  )

  t.eq(
    hmac.sha256(LARGE_PASSWORD, LARGE_DATA),
    hmac.sha256(LARGE_PASSWORD, LARGE_DATA),
    'same hmac',
  )
})
