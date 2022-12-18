import Device from "./lib/device"

const hall = new Device(
  "192.168.0.100", //ip
  "13684365e0980607986f", //id
  "f33444a6362a9664", //key
  3.3 //ver
)

const kitchen = new Device(
  "192.168.0.136", //ip
  "d7573e1270a68a31b5rabw", //id
  "5f1d2d9650e289e9", //key
  3.4 //ver
)

const washroom = new Device(
  "192.168.0.105", //ip
  "13684365e098060744e8", //id
  "ce3d019c816cd28c", //key
  3.3 //ver
)

washroom.connect()
