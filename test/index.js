'use strict'

const test = require('tape')

const crypto = require('..')


const data = 'data'
const password = 'secret'

test('Random bytes', async t => {
    const buffer = await crypto.randomBytes(10)

    t.equal(buffer.length, 10)

    t.end()
})

test('SHA-256', t => {
    t.equal(crypto.sha256(data).toString('hex'), `3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7`)

    t.end()
})

test('HMAC', t => {
    t.equal(crypto.hmac.sha256(data, password).toString('hex'), `1b2c16b75bd2a870c114153ccda5bcfca63314bc722fa160d690de133ccbb9db`)
    t.equal(crypto.hmac.sha256(data, password).toString('base64'), `GywWt1vSqHDBFBU8zaW8/KYzFLxyL6Fg1pDeEzzLuds=`)

    t.end()
})

test('SCRYPT', async t => {
    const key = await crypto.scrypt(data, password, 32)
    const sameKey = await crypto.scrypt(data, password, 32)
    const anotherKey = await crypto.scrypt(data, password, 32, { N: 4 })

    t.ok(key.equals(sameKey))
    t.notOk(key.equals(anotherKey))

    const hash = await crypto.scrypt.hash(data, password)

    t.ok(await crypto.scrypt.verify(data, password, hash))
    t.ok(await crypto.scrypt.verify(data, password, hash.toString('base64')))
    t.notOk(await crypto.scrypt.verify('wrong data', password, hash))

    t.end()
})

test('AES-256', async t => {
    const encrypted = await crypto.aes256.encrypt(data, password)
    const decrypted = await crypto.aes256.decrypt(encrypted, password)

    t.equal(decrypted.toString('utf8'), data)

    t.end()
})
