package scuttlebutt.handshake.messages

import org.abstractj.kalium.NaCl.sodium
import org.abstractj.kalium.NaCl.Sodium.CRYPTO_AUTH_HMACSHA512256_BYTES
import org.abstractj.kalium.NaCl.Sodium.CRYPTO_SCALARMULT_CURVE25519_SCALARBYTES
import org.abstractj.kalium.crypto.Util.zeros

/**
  *  Once a Scuttlebutt client has discovered the IP address, port number and
  *  public key of a peer they can connect via TCP to ask for updates and
  *  exchange messages.
  *
  *  The connection begins with a 4-step handshake to authenticate each peer and
  *  set up an encrypted channel.

  *  The handshake uses the [Secret Handshake key
  *  exchange](https://dominictarr.github.io/secret-handshake-paper/shs.pdf).
  *  Implemented as described in the [SSB protocol
  *  spec](https://ssbc.github.io/scuttlebutt-protocol-guide/#implementations).
  */


object SharedSecretDerivation {

  type sharedSecret_ab = Array[Byte]
  type sharedSecret_aB = Array[Byte]

  def clientDerives (
    client_ephemeral_sk: Array[Byte],
    server_ephemeral_pk: Array[Byte],
    server_longterm_pk: Array[Byte],
  ): (sharedSecret_ab, sharedSecret_aB) = {
    // NOTE this gets mutated
    val shared_secret_ab: Array[Byte] =
      zeros(CRYPTO_SCALARMULT_CURVE25519_SCALARBYTES)
    nacl_scalarmult(
      shared_secret_ab,
      client_ephemeral_sk,
      server_ephemeral_pk
    )
    val shared_secret_aB: Array[Byte] =
      zeros(CRYPTO_SCALARMULT_CURVE25519_SCALARBYTES)
    nacl_scalarmult(
      shared_secret_aB,
      client_ephemeral_sk,
      // Note that long term keys are Ed25519 and must first be converted to
      // Curve25519.
      // TODO
      // https://github.com/abstractj/kalium/blob/1953f8698870200b8fc80f518840d3a9342da31a/src/main/java/org/abstractj/kalium/NaCl.java#L485
      pk_to_curve25519(server_longterm_pk)
    )
    (Array(), Array())
  }


  def serverDerives (
    server_ephemeral_sk: Array[Byte],
    client_ephemeral_pk: Array[Byte],
    server_longterm_sk: Array[Byte]
  ): (sharedSecret_ab, sharedSecret_aB) = {
    // shared_secret_ab = nacl_scalarmult(
    //   server_ephemeral_sk,
    //   client_ephemeral_pk
    // )
    // shared_secret_aB = nacl_scalarmult(
    //   sk_to_curve25519(server_longterm_sk),
    //   client_ephemeral_pk
    // )
    (Array(), Array())
  }

}


object Messages {

  type Curve25519PublicKey = Array[Byte]
  type Ed25519PublicKey = Array[Byte]
  type NetworkIdentifier = Array[Byte]
  type SharedSecret = Array[Byte]

  class HelloMessage {

    /** Produces a signature appended to a message, signed with a shared, secret
      * key. */
    def signed (
      message: Array[Byte],
      sharedKey: Array[Byte]
    ): Array[Byte] = {

      require(message.size == 32)
      require(sharedKey.size == 32)

      /* `hmac` is a function that allows verifying that a message came from
       * someone who knows the secret key. In this case the network identifier is
       * used as the secret key.
       *
       * Throughout the protocol, all instances of hmac use HMAC-SHA-512-256. */
      val hmac: Array[Byte] =
        new Array(CRYPTO_AUTH_HMACSHA512256_BYTES)

      // NOTE side-effecty - modifies `mac`
      sodium()
        .crypto_auth_hmacsha512256(
          // the buffer array to write the signautre to
          hmac,
          // data to sign
          message,
          // message length
          32,
          // the shared key
         sharedKey
        )
      // return a 64-byte array
      // the signature signed w shared secret key + the payload
      hmac ++ message
    }


    /** Verifies that a `signed` message was indeed signed with the given `sharedKey` */
    def verified (
      signed: Array[Byte],
      sharedKey: Array[Byte]
    ): Option[Array[Byte]] = {
      require(signed.size == 64)

      val signature = signed.slice(0, 32)
      val message = signed.slice(32, 64)

      sodium().crypto_auth_hmacsha512256_verify(
        signature,
        message,
        32,
        sharedKey,
        ) match {
        // If verified, return the message
        case 0 => Some(message)
        // if signature forged or tampered with, return None
        case _ => None
      }
    }
  }

  /** Step 1 - Client sends CientHello to Server */
  object ClientHello extends HelloMessage {

    /** First the client sends their =a= generated ephemeral key. Also included is
      * an hmac that indicates the client wishes to use their key with this
      * specific instance of the Scuttlebutt network.
      *
      * @param clientEphemeralPk The client's generated ephemeral key.
      *
      * @param networkIdentifier: The =N=  network identifier is a fixed 32-byte
      * key. Changing the key allows separate networks to be created, for
      * example private networks or testnets. An eavesdropper cannot extract the
      * network identifier directly from what is sent over the wire, although
      * they could confirm a guess that it is the main Scuttlebutt network
      * because that identifier is publicly known. */
    def produce (
      clientEphemeralPk: Array[Byte],
      networkIdentifier: Array[Byte],
    ): Array[Byte] =
      signed(clientEphemeralPk, networkIdentifier)

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
    ): Option[Curve25519PublicKey] =
      verified(msg, networkIdentifier)

  }


  /** Step 2 - Server responds to Client with ServerHello. */
  object ServerHello extends HelloMessage {

    /** The server responds with their own  ephemeral public key and hmac. **/
    def produce (
      serverEphemeralPk: Curve25519PublicKey,
      networkIdentifier: NetworkIdentifier,
    ): Array[Byte] =
      signed(serverEphemeralPk, networkIdentifier)

    /** The client will verifies that they are also using the same
      * network identifier, and will store the server's key */
    def getServerEphemeralKey (
      msg: Array[Byte],
      // network identifier is the shared secret
      networkIdentifier: NetworkIdentifier
    ): Option[Curve25519PublicKey] =
      verified(msg, networkIdentifier)
  }


  object ClientAccept {

    /** The client reveals their identity to the server by sending their long term
      * public key =A=. The client also makes a signature using their long term
      * secret key =A=. By signing the keys used earlier in the handshake the
      * client proves their identity and confirms that they do indeed wish to be
      * part of this handshake.
      *
      *  The client’s message is enclosed in a secret box to ensure that only the
      *  server can read it. Upon receiving it, the server opens the box, stores
      *  the client’s long term public key and verifies the signature. */
    def produce (
      networkIdentifier: NetworkIdentifier,
      serverLongTermPk: Ed25519PublicKey,
      clientLongTermPk: Ed25519PublicKey,
      sharedSecret_ab: SharedSecret,
      sharedSecret_aB: SharedSecret
    ): Array[Byte] = {

      /* Detached signatures do not contain a copy of the message that was signed,
      only a tag that allows verifying the signature if you already know the
      message.

      Here it is okay because the server knows all the information needed to
      reconstruct the message that the client signed. */

      // detached_signature_A = nacl_sign_detached(
      //   msg: concat(
      //     network_identifier,
      //     server_longterm_pk,
      //     sha256(shared_secret_ab)
      //   ),
      //   key: client_longterm_sk
      // )
      // nacl_secret_box(
      //   msg: concat(
      //     detached_signature_A,
      //     client_longterm_pk
      //   ),

      /*
        An all-zero nonce is used for the secret box. The secret box
        construction requires that all secret boxes using a particular key must
        use different nonces. It’s important to get this detail right because
        reusing a nonce will allow an attacker to recover the key and encrypt or
        decrypt any secret boxes using that key. Using a zero nonce is allowed
        here because this is the only secret box that ever uses the key
        sha256(concat(=N= , * =a*b=, =a*B=)). */

      //   nonce: 24_bytes_of_zeros,
      //   key: sha256(
      //     concat(
      //       network_identifier,
      //       shared_secret_ab,
      //       shared_secret_aB
      //     )
      //   )
      // )
      Array()
    }

  }

  object ServerAccept {}

}
