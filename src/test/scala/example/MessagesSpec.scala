package scuttlebutt.handshake.messages

import org.abstractj.kalium.keys.KeyPair

import org.scalatest._

class ClientHelloSpec extends FlatSpec with Matchers {

  val kp = new KeyPair()
  val clientPk = kp.getPublicKey().toBytes
  val clientSk = kp.getPrivateKey().toBytes
  val networkKey = ((new KeyPair) getPublicKey) toBytes

  "Messages.ClientHello::produce" should "take something from kalium's keys, and ::getClientEphemeralKey should decode it, if it has the same networkKey" in {

    println("client pk", clientPk)

    val arr: Array[Byte] = Messages.ClientHello.produce(
      clientPk,
      networkKey
    )
    arr.size shouldBe 64
    arr.slice(32, 64) shouldBe clientPk

    val clientEph: Option[Array[Byte]] =
      Messages.ClientHello.getClientEphemeralKey(
        arr,
        networkKey
      )

    (clientEph.get.sameElements(clientPk)) shouldBe true
  }

  // TODO should return None with diff network keys
}
