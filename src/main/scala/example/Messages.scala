package scuttlebutt.handshake.messages

import org.abstractj.kalium.NaCl.sodium
import org.abstractj.kalium.NaCl.Sodium.CRYPTO_AUTH_HMACSHA512256_BYTES

/**
  *  Once a Scuttlebutt client has discovered the IP address, port number and
  *  public key of a peer they can connect via TCP to ask for updates and
  *  exchange messages.
  *
  *  The connection begins with a 4-step handshake to authenticate each peer and
  *  set up an encrypted channel.

  *  The handshake uses the [Secret Handshake key
  *  exchange](https://dominictarr.github.io/secret-handshake-paper/shs.pdf).
  */


object Messages {

  type Curve25519PublicKey = Array[Byte]
  type NetworkIdentifier = Array[Byte]

  /*
   Step 1 -
   Client sends CientHello to Server
   */

  object ClientHello {

    /** First the client sends their =a= generated ephemeral key. Also included is
      * an hmac that indicates the client wishes to use their key with this
      * specific instance of the Scuttlebutt network.

      * The =N=  network identifier is a fixed 32-byte key.
      *
      * Changing the key allows separate networks to be created, for example
      * private networks or testnets. An eavesdropper cannot extract the network
      * identifier directly from what is sent over the wire, although they could
      * confirm a guess that it is the main Scuttlebutt network because that
      * identifier is publicly known.
      *
      *
      * `hmac` is a function that allows verifying that a message came from
      * someone who knows the secret key. In this case the network identifier is
      * used as the secret key.
      *
      * Throughout the protocol, all instances of hmac use HMAC-SHA-512-256. */
    def produce (
      clientEphemeralPk: Array[Byte],
      networkIdentifier: Array[Byte],
    ): Array[Byte] = {
      require(clientEphemeralPk.size == 32)
      require(networkIdentifier.size == 32)
      val mac: Array[Byte] = new Array(CRYPTO_AUTH_HMACSHA512256_BYTES)
      // NOTE side-effecty - modifies `mac`
      sodium()
        .crypto_auth_hmacsha512256(
          mac,
          networkIdentifier,
          32,
          clientEphemeralPk
        )
      // return a 64-byte array
      mac ++ clientEphemeralPk
    }

    /** The server stores the client’s ephemeral public key and uses the hmac to
      * verify that the client is using the same network identifier.
      *
      * Both the message creator and verifier have to know the same message and
      * secret key for the verification to succeed, but the secret key is not
      * revealed to an eavesdropper. */
    def getClientEphemeralKey (
      msg: Array[Byte],
      // network identifier is the shared secret
      networkIdentifier: NetworkIdentifier
    ): Option[Curve25519PublicKey]= {
      require(msg.size == 64)

      val client_hmac = msg.slice(0, 32)
      val client_ephemeral_pk = msg.slice(32, 64)

      sodium().crypto_auth_hmacsha512256_verify(
        client_hmac,
        client_ephemeral_pk,
        32,
        networkIdentifier
      ) match {
        case 0 => Some(client_ephemeral_pk)
        case _ => None
      }
      // assert_nacl_auth_verify(
      //   authenticator: client_hmac,
      //   msg: client_ephemeral_pk,
      // // matches my secret key, the network ID?
      //   key: network_identifier
      // )

      // TODO remove
      None
    }
  }


  /*
   Step 2 -
   Server responds to Client with ServerHello.
   */


  object ServerHello {

    /** The server responds with their own  ephemeral public key =b= and hmac. **/
    def produce (
      clientEphemeralPk: Curve25519PublicKey,
      networkIdentifier: String
    ): Array[Byte] = {
      // 64-byte array
      // concat(
      // TODO crypto_auth_hmacsha512256
      //   nacl_auth(
      //     msg: server_ephemeral_pk,
      //     key: network_identifier
      //   ),
      //   server_ephemeral_pk
      // )
      Array()
    }

    /** The client stores the key and verifies that they are also using the same
      * network identifier. */
    def getServerEphemeralKey (
      msg: Array[Byte],
      // network identifier is the shared secret
      networkIdentifier: Array[Long]
    ): Option[Curve25519PublicKey] = {
      require(msg.size == 64)
      //     server_hmac = first_32_bytes(msg2)
      //     server_ephemeral_pk = last_32_bytes(msg2)
      // TODO crypto_auth_hmacsha512256_verify
      //     assert_nacl_auth_verify(
      //       authenticator: server_hmac,
      //       msg: server_ephemeral_pk,
      //       key: network_identifier
      // )
      // TODO remove
      None
    }
  }

  // TODO shared secret derivation I

  object ClientAccept {}

  // TODO shared secret derivation II

  object ServerAccept {}

}

