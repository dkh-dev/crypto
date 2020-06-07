'use strict'

const test = require('tape')


const tape = (name, callback) => {
  test(name, t => {
    /**
     * @override
     * @async
     */
    t.throws = async (fn, msg) => {
      try {
        await fn()

        t.fail(msg)
      } catch (error) {
        t.pass(msg)
      }
    }

    /**
     * @override
     * @async
     */
    t.true = async (value, msg) => {
      t.ok(await value, msg)
    }

    t.is = (actual, expected, msg) => {
      if (expected instanceof Buffer) {
        t.ok(expected.equals(actual), msg)
      } else {
        t.equal(actual, expected, msg)
      }
    }

    t.not = (actual, expected, msg) => {
      if (expected instanceof Buffer) {
        t.notOk(expected.equals(actual), msg)
      } else {
        t.notEqual(actual, expected, msg)
      }
    }

    t.resolves = async (promise, msg) => {
      try {
        await promise

        t.pass(msg)
      } catch (error) {
        t.fail(msg)
      }
    }

    t.rejects = async (promise, msg) => {
      try {
        await promise

        t.fail(msg)
      } catch (error) {
        t.pass(msg)
      }
    }

    callback(t)
  })
}

module.exports = tape
