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
 * Promisifies `stream.Transform`.
 */
const stream = (stream, data) => new Promise((resolve, reject) => {
  const chunks = []

  stream.on('error', reject)
  stream.on('readable', () => {
    let chunk

    while (chunk = stream.read()) {
      chunks.push(chunk)
    }
  })
  stream.on('end', () => {
    const buffer = Buffer.concat(chunks)

    resolve(buffer)
  })

  const { pipe } = data

  if (pipe && pipe.call && pipe.apply) {
    data.pipe(stream)
  } else {
    stream.write(data)
    stream.end()
  }
})

module.exports = {
  callback,
  stream,
}
