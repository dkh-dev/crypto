'use strict'

/**
 * Splits a Buffer into chunks of the defined sizes.
 */
const split = (buffer, sizes, offset, last = false) => {
  let start = offset

  const chunks = []

  sizes.forEach(size => {
    chunks.push(buffer.slice(start, start + size))

    start += size
  })

  if (last) {
    chunks.push(buffer.slice(start))
  }

  return chunks
}

const read = (buffer, sizes, offset = 0) => {
  let start = offset

  return sizes.map(size => {
    const value = buffer.readUIntBE(start, size)

    start += size

    return value
  })
}

const from = (sizes, numbers) => {
  const chunks = sizes.map((size, i) => {
    const buffer = Buffer.alloc(size)

    buffer.writeUIntBE(numbers[ i ], 0, size)

    return buffer
  })

  return Buffer.concat(chunks)
}

module.exports = {
  split,
  read,
  from,
}
