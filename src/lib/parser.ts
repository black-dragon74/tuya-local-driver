import { COMMAND_TYPE, HEADER_SIZE } from "./const"
import crc from "./crc"
import Cipher from "./cipher"

interface IParser {
  key: string
  version: number
  cipher: Cipher
}

type Frame = {
  payload: Buffer
  command: COMMAND_TYPE
  sequence: number
}

class Parser implements IParser {
  key: string

  version: number

  cipher: Cipher

  constructor(key: string, version: number) {
    this.key = key
    this.version = version

    if (key.length !== 16) {
      throw new Error("Invalid key length")
    }

    this.cipher = new Cipher(key, version)
  }

  encode(frame: Frame, encrypted: boolean) {
    if (this.version === 3.4) {
      return this.encodeNewVersion(frame, encrypted)
    }

    return this.encodeOldVersion(frame, encrypted)
  }

  splitPackets(data: Buffer): Buffer[] {
    const packets: Buffer[] = []

    const empty = Buffer.from("")

    while (!data.equals(empty)) {
      const startIndex = data.indexOf(Buffer.from("000055aa", "hex"))
      const endIndex = data.indexOf(Buffer.from("0000aa55", "hex")) + 4

      packets.push(data.subarray(startIndex, endIndex))

      data = data.subarray(endIndex, data.length)
    }

    return packets
  }

  parsePacket(buffer: Buffer): Frame {
    if (buffer.length < 24) {
      throw new Error("Invalid packet length")
    }

    const prefix = buffer.readUInt32BE(0)

    if (prefix !== 0x000055aa) {
      throw new Error(`Prefix does not match: ${buffer.toString("hex")}`)
    }

    // Check for suffix
    const suffix = buffer.readUInt32BE(buffer.length - 4)

    if (suffix !== 0x0000aa55) {
      throw new TypeError(`Suffix does not match: ${buffer.toString("hex")}`)
    }

    // Get sequence number
    const sequenceN = buffer.readUInt32BE(4)

    // Get command byte
    const commandByte = buffer.readUInt32BE(8)

    // Get payload size
    const payloadSize = buffer.readUInt32BE(12)

    // Check for payload
    if (buffer.length - 8 < payloadSize) {
      throw new Error(
        `Packet missing payload: payload has length ${payloadSize}.`
      )
    }

    const packageFromDiscovery =
      commandByte === COMMAND_TYPE.UDP ||
      commandByte === COMMAND_TYPE.UDP_NEW ||
      commandByte === COMMAND_TYPE.BOARDCAST_LPV34

    const returnCode = buffer.readUInt32BE(16)

    let payload: Buffer
    console.log("Buffer length: " + buffer.length)

    if (returnCode & 0xffffff00) {
      if (this.version === 3.4 && !packageFromDiscovery) {
        payload = buffer.subarray(HEADER_SIZE, HEADER_SIZE + payloadSize - 0x24)
      } else {
        payload = buffer.subarray(HEADER_SIZE, HEADER_SIZE + payloadSize - 8)
      }
    } else if (this.version === 3.4 && !packageFromDiscovery) {
      payload = buffer.subarray(
        HEADER_SIZE + 4,
        HEADER_SIZE + payloadSize - 0x24
      )
    } else {
      console.log("No additonal ops")

      payload = buffer.subarray(HEADER_SIZE + 4, HEADER_SIZE + payloadSize - 8)
      console.log("Payload length: " + payload.length)
    }

    // Check CRC
    if (this.version === 3.4 && !packageFromDiscovery) {
      const expectedCrc = buffer
        .subarray(HEADER_SIZE + payloadSize - 0x24, buffer.length - 4)
        .toString("hex")
      const computedCrc = this.cipher
        .hmac(
          buffer.subarray(0, HEADER_SIZE + payloadSize - 0x24).toString("hex")
        )
        .toString("hex")

      if (expectedCrc !== computedCrc) {
        throw new Error(
          `HMAC mismatch: expected ${expectedCrc}, was ${computedCrc}. ${buffer.toString(
            "hex"
          )}`
        )
      }
    } else {
      const expectedCrc = buffer.readInt32BE(HEADER_SIZE + payloadSize - 8)
      const computedCrc = crc(buffer.subarray(0, payloadSize + 8))

      if (expectedCrc !== computedCrc) {
        throw new Error(
          `CRC mismatch: expected ${expectedCrc}, was ${computedCrc}. ${buffer.toString(
            "hex"
          )}`
        )
      }
    }

    return {
      payload,
      command: commandByte,
      sequence: sequenceN,
    }
  }

  getPayload(data: Buffer): string {
    if (data.length === 0) {
      throw new Error("Invalid payload length")
    }

    let ret: string

    // Try to decrypt data first.
    try {
      ret = this.cipher.decrypt(data)
    } catch (_) {
      ret = data.toString("utf8")
    }

    return ret
  }

  parse(data: Buffer): Frame {
    const f = this.parsePacket(data)
    const pld = this.getPayload(f.payload)

    f.payload = Buffer.from(pld)

    return f
  }

  private encodeOldVersion(frame: Frame, encrypt: boolean) {
    let payload: Buffer = frame.payload

    // Protocol 3.3 and 3.2 is always encrypted
    if (this.version === 3.3 || this.version === 3.2) {
      // Encrypt data
      payload = this.cipher.encrypt(frame.payload, false) as Buffer

      // Check if we need an extended header, only for certain CommandTypes
      if (
        frame.command !== COMMAND_TYPE.DP_QUERY &&
        frame.command !== COMMAND_TYPE.DP_REFRESH
      ) {
        // Add 3.3 header
        const buffer = Buffer.alloc(payload.length + 15)
        Buffer.from("3.3").copy(buffer, 0)
        payload.copy(buffer, 15)
        payload = buffer
      }
    } else if (encrypt) {
      // Protocol 3.1 and below, only encrypt data if necessary
      payload = Buffer.from(this.cipher.encrypt(frame.payload) as string)

      // Create MD5 signature
      const md5 = this.cipher.md5(
        "data=" + payload + "||lpv=" + this.version + "||" + this.key
      )

      // Create byte buffer from hex data
      payload = Buffer.from(this.version.toString() + md5 + payload)
    }

    // Allocate buffer with room for payload + 24 bytes for
    // prefix, sequence, command, length, crc, and suffix
    const buffer = Buffer.alloc(payload.length + 24)

    // Add prefix, command, and length
    buffer.writeUInt32BE(0x000055aa, 0)
    buffer.writeUInt32BE(frame.command, 8)
    buffer.writeUInt32BE(payload.length + 8, 12)

    if (frame.sequence) {
      buffer.writeUInt32BE(frame.sequence, 4)
    }

    // Add payload, crc, and suffix
    payload.copy(buffer, 16)
    const calculatedCrc = crc(buffer.slice(0, payload.length + 16)) & 0xffffffff

    buffer.writeInt32BE(calculatedCrc, payload.length + 16)
    buffer.writeUInt32BE(0x0000aa55, payload.length + 20)

    return buffer
  }

  private encodeNewVersion(frame: Frame, _encrypt: boolean) {
    let payload = frame.payload

    if (
      frame.command !== COMMAND_TYPE.DP_QUERY &&
      frame.command !== COMMAND_TYPE.HEART_BEAT &&
      frame.command !== COMMAND_TYPE.DP_QUERY_NEW &&
      frame.command !== COMMAND_TYPE.SESS_KEY_NEG_START &&
      frame.command !== COMMAND_TYPE.SESS_KEY_NEG_FINISH &&
      frame.command !== COMMAND_TYPE.DP_REFRESH
    ) {
      // Add 3.4 header
      // check this: mqc_very_pcmcd_mcd(int a1, unsigned int a2)
      const buffer = Buffer.alloc(payload.length + 15)
      Buffer.from("3.4").copy(buffer, 0)
      payload.copy(buffer, 15)
      payload = buffer
    }

    // ? if (payload.length > 0) { // is null messages need padding - PING work without
    const padding = 0x10 - (payload.length & 0xf)
    const buf34 = Buffer.alloc(payload.length + padding, padding)
    payload.copy(buf34)
    payload = buf34
    // }

    payload = Buffer.from(this.cipher.encrypt(frame.payload))

    // Allocate buffer with room for payload + 24 bytes for
    // prefix, sequence, command, length, crc, and suffix
    const buffer = Buffer.alloc(payload.length + 52)

    // Add prefix, command, and length
    buffer.writeUInt32BE(0x000055aa, 0)
    buffer.writeUInt32BE(frame.command, 8)
    buffer.writeUInt32BE(payload.length + 0x24, 12)

    if (frame.sequence) {
      buffer.writeUInt32BE(frame.sequence, 4)
    }

    // Add payload, crc, and suffix
    payload.copy(buffer, 16)
    const calculatedCrc = this.cipher.hmac(
      buffer.subarray(0, payload.length + 16).toString("hex"),
      false
    ) as Buffer // & 0xFFFFFFFF;
    calculatedCrc.copy(buffer, payload.length + 16)

    buffer.writeUInt32BE(0x0000aa55, payload.length + 48)
    return buffer
  }
}

export default Parser
