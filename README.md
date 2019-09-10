# crypto

_A wrapper for some `crypto` Node.js APIs_

## Installation

```bash
$ yarn add @dkh-dev/crypto
```

## Examples

### Random bytes

```javascript
'use strict'

const { randomBytes } = require('@dkh-dev/crypto')

const main = async () => {
    console.log(await randomBytes(3))
    console.log(await randomBytes(3, { encoding: 'hex' }))
    // => <Buffer 86 70 d6>
    //    731c05
}

main()
```

### SHA-256

```javascript
'use strict'

const { sha256 } = require('@dkh-dev/crypto')

console.log(sha256('data'))
// => 3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7
```

### HMAC

```javascript
'use strict'

const { hmac } = require('@dkh-dev/crypto')

console.log(hmac.sha256('data', 'secret', { encoding: 'base64' }))
// => GywWt1vSqHDBFBU8zaW8/KYzFLxyL6Fg1pDeEzzLuds=
```

### AES-256-GCM

```javascript
'use strict'

const { aes256 } = require('@dkh-dev/crypto')

const data = 'data'
const password = 'secret'
const encoding = 'base64'

const main = async () => {
    const encrypted = await aes256.encrypt(data, password, { encoding })
    const decrypted = await aes256.decrypt(encrypted, password, { encoding })

    console.log(encrypted)
    console.log(decrypted === data)
    // => 8j91Ec9Rd1v69XCQFKOtUivtRyITPWcv17MM4DlTyz+ZIW3Pw8OB3Cm9b9Ln7zxAW8alSw==
    //    true
}

main()
```
