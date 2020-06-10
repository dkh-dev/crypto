'use strict'

const fs = require('fs')

const test = require('./utils/tape')

const { aes256, box, hash, hmac, randomBytes, scrypt } = require('..')

/* eslint-disable max-len, max-statements */

const DATA = 'data'
const PASSWORD = 'secret'
const SHA256_HASH = 'Om6weQ85rIfJTzhWst0sXREOaBFgImGpqSPTuyOtyLc='
const SHA256_HMAC = 'GywWt1vSqHDBFBU8zaW8/KYzFLxyL6Fg1pDeEzzLuds='
const LARGE_DATA = '0123456789'.repeat(1e6)
const LARGE_PASSWORD = '9876543210'.repeat(1e6)
const INVALID_DATA = DATA.toUpperCase()
const INVALID_PASSWORD = PASSWORD.toUpperCase()
const AAD = Buffer.from('aad')
const INVALID_AAD = Buffer.from('invalid-aad')


test('box', async t => {
  const privateKey = box.createPrivateKey(fs.readFileSync(`${ __dirname }/key.pem`))
  const publicKey = box.createPublicKey(fs.readFileSync(`${ __dirname }/key.pub`))

  const encrypted = await box.seal(publicKey, DATA)
  const decrypted = await box.open(privateKey, encrypted)

  t.is(decrypted.toString(), DATA, 'public encrypt private decrypt')

  t.throws(() => box.open(publicKey, DATA), 'box can only opened using private key')

  {
    const encrypted = await box.seal(privateKey, DATA)
    const decrypted = await box.open(privateKey, encrypted)

    t.is(decrypted.toString(), DATA, 'seal accepts private key as well')
  }

  {
    const encrypted = await box.seal(publicKey, LARGE_DATA)
    const decrypted = await box.open(privateKey, encrypted)

    t.is(decrypted.toString(), LARGE_DATA, 'large box data')
  }

  {
    const encrypted = await box.seal(publicKey, DATA, AAD)
    const decrypted = await box.open(privateKey, encrypted, AAD)

    t.is(decrypted.toString(), DATA, 'seal a box with aad')

    t.rejects(box.open(privateKey, encrypted, INVALID_AAD), 'invalid box aad')
  }

  t.end()
})

test('aes256', async t => {
  const encrypted = await aes256.encrypt(PASSWORD, DATA)
  const decrypted = await aes256.decrypt(PASSWORD, encrypted)

  t.is(decrypted.toString(), DATA, 'the decrypted string equals to the input data')

  t.resolves(aes256.encrypt(PASSWORD, LARGE_DATA), 'large data')
  t.resolves(aes256.encrypt(LARGE_PASSWORD, DATA), 'large password')
  t.resolves(aes256.decrypt(PASSWORD, encrypted), 'encrypted data must be of type Buffer')
  t.rejects(aes256.encrypt(PASSWORD), 'data must not be empty')
  t.rejects(aes256.encrypt(null, DATA), 'password must not be empty')

  {
    const encrypted = await aes256.encrypt(LARGE_PASSWORD, LARGE_DATA)
    const decrypted = await aes256.decrypt(LARGE_PASSWORD, encrypted)

    t.is(decrypted.toString() === LARGE_DATA, true, 'decrypted large data')
  }

  {
    const encrypted = await aes256.encrypt(PASSWORD, DATA, AAD)
    const decrypted = await aes256.decrypt(PASSWORD, encrypted, AAD)

    t.is(decrypted.toString() === DATA, true, 'encryption and decryption with aad')

    t.rejects(aes256.decrypt(PASSWORD, encrypted, INVALID_AAD), 'invalid aad')
  }

  t.end()
})

test('scrypt.hash', async t => {
  const buffer = await scrypt.hash(PASSWORD, DATA)

  t.is(await scrypt.verify(PASSWORD, DATA, buffer), true, 'authenticated data')
  t.is(await scrypt.verify(PASSWORD, INVALID_DATA, buffer), false, 'invalid data')
  t.is(await scrypt.verify(INVALID_PASSWORD, DATA, buffer), false, 'invalid password')

  t.resolves(scrypt.hash(PASSWORD, LARGE_DATA), 'scrypt hash large data')
  t.resolves(scrypt.hash(LARGE_PASSWORD, DATA), 'scrypt hash large password')
  t.rejects(scrypt.hash(PASSWORD), 'data must not be empty')
  t.rejects(scrypt.hash(null, DATA), 'password must not be empty')
  t.rejects(scrypt.hash(PASSWORD, DATA, { N: 4, r: 256, p: 1 }), 'invalid options.r')
  t.rejects(scrypt.hash(PASSWORD, DATA, { N: 4, r: 1, p: 256 }), 'invalid options.p')

  {
    const buffer = await scrypt.hash(LARGE_PASSWORD, LARGE_DATA)

    t.true(await scrypt.verify(LARGE_PASSWORD, LARGE_DATA, buffer) === true, 'authenticated data')
  }

  {
    const options = Object.freeze({ N: 2 ** 12, r: 16, p: 2 })
    const buffer = await scrypt.hash(PASSWORD, DATA, options)

    t.is(await scrypt.verify(PASSWORD, DATA, buffer), true, 'user-defined scrypt options')
  }

  t.end()
})

test('scrypt.scryptiv', async t => {
  const ivSize = { logN: 2, r: 4, p: 4 }
  const saltSize = 64

  const iv = scrypt.deriveIv({ N: 2 ** 11, r: 15, p: 3 }, ivSize)
  const salt = await randomBytes(saltSize)
  const buffer = await scrypt.scryptiv(PASSWORD, iv, salt, DATA)

  t.is(await scrypt.verify(PASSWORD, DATA, buffer), true, 'a hash should include sufficient information for verification')

  t.end()
})

test('scrypt.scrypt', async t => {
  const key = await scrypt.scrypt(DATA, PASSWORD, 32)
  const same = await scrypt.scrypt(DATA, PASSWORD, 32)
  const different = await scrypt.scrypt(DATA, PASSWORD, 32, { N: 4 })

  t.is(key.length, 32, 'scrypt derived key size equals to the defined size')
  t.is(key, same, 'same input produces same hash')
  t.not(key, different, 'different input')

  t.end()
})

test('randomBytes', async t => {
  const buffer = await randomBytes(10)

  t.is(buffer.length, 10, 'buffer size equals to the specified size')

  t.rejects(randomBytes('invalid'), 'size must be of type number')

  t.end()
})

test('hash.sha256', async t => {
  const buffer = await hash.sha256(DATA)

  t.is(buffer.length * 8, 256, 'sha256 hash size is 256 bits')
  t.is(buffer.toString('base64'), SHA256_HASH, 'same hash')

  t.is(await hash.sha256(DATA), buffer, 'same hash for same data')
  t.not(await hash.sha256(INVALID_DATA), buffer, 'invalid data')

  t.resolves(hash.sha256(LARGE_DATA), 'hash large data')

  t.end()
})

test('hmac.sha256', async t => {
  const buffer = await hmac.sha256(PASSWORD, DATA)

  t.is(buffer.length * 8, 256, 'hmac sha256 size is equal to sha256 hash size of 256 bits')
  t.is(buffer.toString('base64'), SHA256_HMAC, 'same hmac')

  t.is(await hmac.sha256(PASSWORD, DATA), buffer, 'same hmac for same data and password')
  t.not(await hmac.sha256(PASSWORD, INVALID_DATA), buffer, 'invalid data')
  t.not(await hmac.sha256(INVALID_PASSWORD, DATA), buffer, 'invalid passwords')

  t.resolves(hmac.sha256(PASSWORD, LARGE_DATA), 'large data')
  t.resolves(hmac.sha256(LARGE_PASSWORD, DATA), 'large password')
  t.throws(() => hmac.sha256(PASSWORD), 'data must not be empty')
  t.throws(() => hmac.sha256(null, DATA), 'password must not be empty')

  {
    const buffer = await hmac.sha256(LARGE_PASSWORD, LARGE_DATA)

    t.is(await hmac.sha256(LARGE_PASSWORD, LARGE_DATA), buffer, 'same hmac')
  }

  t.end()
})
