import {
  createCipheriv,
  createHash,
  createHmac,
  randomBytes,
  createDecipheriv,
} from "crypto"

interface ICipher {
  key: string
  version: number
}

class Cipher implements ICipher {
  key: string

  sessionKey: string | null

  version: number

  constructor(key: string, version: number) {
    this.key = key
    this.version = version
    this.sessionKey = null
  }

  setSessionKey(sessionKey: string) {
    this.sessionKey = sessionKey
  }

  getKey(): string {
    return this.sessionKey === null ? this.key : this.sessionKey
  }

  // TODO: Maybe accept data as a string?
  encrypt(data: Buffer, useBase64: boolean = true): string | Buffer {
    if (this.version === 3.4) {
      return this.encryptNewVersion(data, useBase64)
    }
    return this.encryptOldVersion(data, useBase64)
  }

  private encryptOldVersion(data: Buffer, useBase64: boolean): string | Buffer {
    const cipher = createCipheriv("aes-128-ecb", this.getKey(), null)

    let encrypted = cipher.update(data.toString("hex"), "utf8", "base64")
    encrypted += cipher.final("base64")

    if (useBase64 === false) {
      return Buffer.from(encrypted, "base64")
    }

    return encrypted
  }

  private encryptNewVersion(data: Buffer, useBase64: boolean): string | Buffer {
    const cipher = createCipheriv("aes-128-ecb", this.getKey(), null)
    cipher.setAutoPadding(false)

    let encrypted = cipher.update(data.toString("hex"), "utf8", "base64")
    encrypted += cipher.final("base64")

    if (useBase64 === false) {
      return Buffer.from(encrypted, "base64")
    }

    return encrypted
  }

  // TODO: Maybe accept data as a string?
  decrypt(data: Buffer): string {
    if (this.version === 3.4) {
      return this.decryptNewVersion(data)
    }

    return this.decryptOldVersion(data)
  }

  private decryptOldVersion(data: Buffer): string {
    // let isb64 = false

    if (data.indexOf(this.version.toString()) === 0) {
      console.log("has header")

      if (this.version === 3.3 || this.version === 3.2) {
        // remove header
        // is buffer
        data = data.subarray(15)
        console.log("no b64")
      } else {
        // b64 encoded
        // is string
        data = data.subarray(19)
        // isb64 = true
        console.log("b64")
      }
    }

    console.log("No header?")

    let result: string | Buffer
    try {
      const decipher = createDecipheriv("aes-128-ecb", this.getKey(), "")
      result = Buffer.concat([decipher.update(data), decipher.final()])
    } catch (_) {
      throw new Error("Decipher failed!")
    }

    return result.toString()
  }

  private decryptNewVersion(data: Buffer): string {
    let result: Buffer | string
    try {
      const decipher = createDecipheriv("aes-128-ecb", this.getKey(), null)
      decipher.setAutoPadding(false)
      result = decipher.update(data)
      decipher.final()
      // Remove padding
      result = result.subarray(0, result.length - result[result.length - 1])
    } catch (_) {
      throw new Error("Decrypt failed")
    }

    if (result.indexOf(this.version.toString()) === 0) {
      // remove header
      result = result.subarray(15)
    }

    return result.toString("utf8")
  }

  md5(data: string, asString: boolean = true): Buffer | string {
    const hash = createHash("md5").update(data, "utf8")

    if (asString) {
      return hash.digest("hex").substring(8, 24)
    }

    return hash.digest().subarray(8, 24)
  }

  hmac(data: string, asString: boolean = true): Buffer | string {
    const hash = createHmac("sha256", this.getKey()).update(data, "utf8")

    if (asString) {
      return hash.digest("hex")
    }

    return hash.digest()
  }

  random(): Buffer {
    return randomBytes(16)
  }
}

export default Cipher
