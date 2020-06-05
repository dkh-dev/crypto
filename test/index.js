'use strict'

const test = require('tape')

const { aes256, hash, hmac, randomBytes, scrypt } = require('..')

/* eslint-disable max-len, max-statements */

const DATA = 'data'
const PASSWORD = 'secret'
const SHA256_HASH = 'Om6weQ85rIfJTzhWst0sXREOaBFgImGpqSPTuyOtyLc='
const SHA256_HMAC = 'GywWt1vSqHDBFBU8zaW8/KYzFLxyL6Fg1pDeEzzLuds='
const LARGE_DATA = '0123456789'.repeat(1000)
const LARGE_PASSWORD = '9876543210'.repeat(1000)
const INVALID_DATA = DATA.toUpperCase()
const INVALID_PASSWORD = PASSWORD.toUpperCase()


test('randomBytes', async t => {
  const buffer = await randomBytes(10)

  t.equal(buffer.length, 10, 'buffer length equals to the specified size')

  try {
    await randomBytes('invalid')

    t.fail('size must be of type number')
  } catch (error) {
    t.ok(error, 'size must be of type number')
  }

  t.end()
})

test('hash.sha256', async t => {
  const buffer = await hash.sha256(DATA)

  t.equal(buffer.length * 8, 256, 'hash length is 256 bits')

  t.equal(buffer.toString('base64'), SHA256_HASH, 'same hash')

  t.ok(buffer.equals(await hash.sha256(DATA)), 'same hash for same data')
  t.notOk(buffer.equals(await hash.sha256(INVALID_DATA)), 'invalid data')

  try {
    await hash.sha256(LARGE_DATA)

    t.ok('hash large data')
  } catch (error) {
    t.fail('hash large data')
  }

  t.end()
})

test('hmac.sha256', async t => {
  const buffer = await hmac.sha256(PASSWORD, DATA)

  t.equal(buffer.length * 8, 256, 'hmac length is equal to sha256 hash length of 256 bits')

  t.equal(buffer.toString('base64'), SHA256_HMAC, 'same hmac')

  t.ok(buffer.equals(await hmac.sha256(PASSWORD, DATA)), 'same hmac for same data and password')
  t.notOk(buffer.equals(await hmac.sha256(PASSWORD, INVALID_DATA)), 'invalid data')
  t.notOk(buffer.equals(await hmac.sha256(INVALID_PASSWORD, DATA)), 'invalid passwords')

  try {
    await hmac.sha256(PASSWORD, LARGE_DATA)
    await hmac.sha256(LARGE_PASSWORD, DATA)

    const buffer = await hmac.sha256(LARGE_PASSWORD, LARGE_DATA)

    t.ok('hmac from large data')

    t.ok(buffer.equals(await hmac.sha256(LARGE_PASSWORD, LARGE_DATA)), 'same hmac')
  } catch (error) {
    t.fail('hmac from large data')
  }

  try {
    await hmac.sha256(PASSWORD)

    t.fail('data must not be empty')
  } catch (error) {
    t.ok('data must not be empty')
  }

  try {
    await hmac.sha256(null, DATA)

    t.fail('password must not be empty')
  } catch (error) {
    t.ok('password must not be empty')
  }

  t.end()
})

test('scrypt.hash and scrypt.verify', async t => {
  const buffer = await scrypt.hash(PASSWORD, DATA)

  t.ok(await scrypt.verify(PASSWORD, DATA, buffer) === true, 'authenticated data')
  t.notOk(await scrypt.verify(PASSWORD, INVALID_DATA, buffer) === true, 'invalid data')
  t.notOk(await scrypt.verify(INVALID_PASSWORD, DATA, buffer) === true, 'invalid password')

  try {
    await scrypt.hash(PASSWORD, LARGE_DATA)
    await scrypt.hash(LARGE_PASSWORD, DATA)

    const buffer = await scrypt.hash(LARGE_PASSWORD, LARGE_DATA)

    t.ok('scrypt hash large data')

    t.ok(await scrypt.verify(LARGE_PASSWORD, LARGE_DATA, buffer), 'authenticated data')
  } catch (error) {
    t.fail('scrypt hash large data')
  }

  try {
    await scrypt.hash(PASSWORD)

    t.fail('data must not be empty')
  } catch (error) {
    t.ok('data must not be empty')
  }

  try {
    await scrypt.hash(null, DATA)

    t.fail('password must not be empty')
  } catch (error) {
    t.ok('password must not be empty')
  }

  t.end()
})

test('aes256', async t => {
  const encrypted = await aes256.encrypt(PASSWORD, DATA)
  const decrypted = await aes256.decrypt(PASSWORD, encrypted)

  t.equal(decrypted.toString(), DATA, 'the decrypted string equals to the input data')

  try {
    await aes256.encrypt(PASSWORD, LARGE_DATA)
    await aes256.encrypt(LARGE_PASSWORD, DATA)

    const encrypted = await aes256.encrypt(LARGE_PASSWORD, LARGE_DATA)
    const decrypted = await aes256.decrypt(LARGE_PASSWORD, encrypted)

    t.ok('encrypt large data')

    t.equal(decrypted.toString(), LARGE_DATA, 'decrypted data')
  } catch (error) {
    t.fail('scrypt hash large data')
  }

  try {
    await aes256.encrypt(PASSWORD)

    t.fail('data must not be empty')
  } catch (error) {
    t.ok('data must not be empty')
  }

  try {
    await aes256.encrypt(null, DATA)

    t.fail('password must not be empty')
  } catch (error) {
    t.ok('password must not be empty')
  }

  t.end()
})

test('scrypt.scrypt', async t => {
  const key = await scrypt.scrypt(DATA, PASSWORD, 32)
  const same = await scrypt.scrypt(DATA, PASSWORD, 32)
  const different = await scrypt.scrypt(DATA, PASSWORD, 32, { N: 4 })

  t.ok(key.length, 32, 'scrypt derived key length equals to the defined length')

  t.ok(key.equals(same), 'same input produces same hash')
  t.notOk(key.equals(different), 'different input')

  t.end()
})
