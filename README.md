# crypto

_A crypto library that is secure, easy to use and hard to misuse_

## Installation

```bash
$ yarn add @dkh-dev/crypto
```

## Examples

### Scrypt

```javascript
'use strict'

const { scrypt } = require('@dkh-dev/crypto')

const main = async () => {
  const data = 'data'
  const password = 'password'

  const hash = await scrypt.hash(password, data)

  console.log(hash.toString('base64'))
  console.log(await scrypt.verify(password, data, hash))
  // => DggBZexpdHVfTclOZY+wiL5DN24ceOFgs2BX3e48CKU/MMKvVUb0MSV3+vGR7zHBtU3hx3f+ryFcgGHqY8GH0r4z6Q==
  //    true
}

main()
```

### AES-256-GCM

```javascript
'use strict'

const { aes256 } = require('@dkh-dev/crypto')

const data = 'data'
const password = 'secret'

const main = async () => {
  const encrypted = await aes256.encrypt(password, data)
  const decrypted = await aes256.decrypt(password, encrypted)

  console.log(encrypted.toString('base64'))
  console.log(decrypted.toString('utf8') === data)
  // => qR1XbghwPYq+iR6rxXdygeZ7mhWYQbWr2rEIr5R9WYJQMU2rAtz95J3OhJAunkmeDex9RA==
  //    true
}

main()
```

### HMAC-SHA256

```javascript
'use strict'

const { hmac } = require('@dkh-dev/crypto')

const data = 'data'
const key = 'secret'

const main = async () => {
  const buffer = await hmac.sha256(key, data)

  console.log(buffer.toString('base64'))
  // => GywWt1vSqHDBFBU8zaW8/KYzFLxyL6Fg1pDeEzzLuds=
}

main()
```

### SHA256

```javascript
'use strict'

const { hash } = require('@dkh-dev/crypto')

const data = 'data'
const key = 'secret'

const main = async () => {
  const buffer = await hash.sha256(key, data)

  console.log(buffer.toString('base64'))
  // => Om6weQ85rIfJTzhWst0sXREOaBFgImGpqSPTuyOtyLc=
}

main()
```

### Random bytes

```javascript
'use strict'

const { randomBytes } = require('@dkh-dev/crypto')

const main = async () => {
  console.log(await randomBytes(3))
  // => <Buffer 86 70 d6>
}

main()
```
