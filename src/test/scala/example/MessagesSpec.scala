package scuttlebutt.handshake.messages

import org.abstractj.kalium.keys.KeyPair

import org.scalatest._

class ClientHelloSpec extends FlatSpec with Matchers {

  val kp = new KeyPair()
  val clientPk = kp.getPublicKey().toBytes
  val clientSk = kp.getPrivateKey().toBytes
  val networkKey = ((new KeyPair) getPublicKey) toBytes

  "Messages.ClientHello::produce" should "take something from kalium's keys, and ::getClientEphemeralKey should decode it, if it has the same networkKey" in {

    val arr: Array[Byte] = Messages.ClientHello.produce(clientPk, networkKey)
    arr.size shouldBe 64

    val clientEph: Option[Array[Byte]] =
      Messages.ClientHello.getClientEphemeralKey(arr, networkKey)

    clientEph shouldBe clientPk
  }
}
