import { Socket } from "net"
import Parser from "./parser"

interface IDevice {
  ip: string
  port: number
  id: string
  key: string
  version: number

  parser: Parser
}

class Device implements IDevice {
  ip: string
  port: number
  id: string
  key: string
  version: number
  parser: Parser
  client: Socket

  constructor(ip: string, id: string, key: string, version: number = 3.3) {
    this.ip = ip
    this.port = 6668
    this.id = id
    this.key = key
    this.version = version

    this.parser = new Parser(key, version)
    this.client = new Socket()

    this.setupListeners()
  }

  connect() {
    this.client.connect(this.port, this.ip)
  }

  private setupListeners() {
    this.client.on("data", data => {
      this.parser.splitPackets(data).forEach(pkt => {
        console.log("Parsing.....")
        const parsed = this.parser.parse(pkt)
        console.log(parsed.payload.toString())
      })
    })

    this.client.on("connect", () => console.log("Connected"))

    this.client.on("error", err => console.log(err))
  }

  disconnect() {
    this.client.end()
    this.client.destroy()
  }
}

export default Device
