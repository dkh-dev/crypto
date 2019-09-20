# crypto

_A wrapper for some `crypto` Node.js APIs_

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

    const hash = await scrypt.hash(data, password)

    console.log(hash.toString('base64'))
    console.log(await scrypt.verify(data, password, hash))
    // => gAgBZabgVkvU18jyc9sdorjPxZIPPFlHlZcg7NCkdDDtdjDGXn5dKWtezrVLs8rxvNsFR6eNadoFUZ8Gr5ElkhKvbg==
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
    const encrypted = await aes256.encrypt(data, password)
    const decrypted = await aes256.decrypt(encrypted, password)

    console.log(encrypted.toString('base64'))
    console.log(decrypted.toString('utf8') === data)
    // => rPxoDwiL0k742Wm2Pjeo8If0D7whePe8+4TooST9qN+n2NiPmqFvWhnvPurgKU6yF1bfcg==
    //    true
}

main()
```

### HMAC

```javascript
'use strict'

const { hmac } = require('@dkh-dev/crypto')

console.log(hmac.sha256('data', 'secret').toString('base64'))
// => GywWt1vSqHDBFBU8zaW8/KYzFLxyL6Fg1pDeEzzLuds=
```

### SHA-256

```javascript
'use strict'

const { sha256 } = require('@dkh-dev/crypto')

console.log(sha256('data').toString('hex'))
// => 3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7
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
