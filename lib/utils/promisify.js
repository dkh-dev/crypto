'use strict'

const callback = callback => (...args) => new Promise((resolve, reject) => {
  callback(...args, (error, value) => {
    if (error) {
      reject(error)
    } else {
      resolve(value)
    }
  })
})

/**
 * Promisify `stream.Transform`.
 */
const stream = (stream, data) => new Promise((resolve, reject) => {
  const chunks = []

  stream.on('error', reject)
  stream.on('readable', () => {
    let chunk

    // eslint-disable-next-line no-cond-assign
    while (chunk = stream.read()) {
      chunks.push(chunk)
    }
  })
  stream.on('end', () => {
    const buffer = Buffer.concat(chunks)

    resolve(buffer)
  })

  stream.write(data)
  stream.end()
})

module.exports = {
  callback,
  stream,
}
