package scuttlebutt

import scala.concurrent.{Future, Await}
import scala.concurrent.forkjoin._
import scala.concurrent.duration._
import scala.concurrent.ExecutionContext.Implicits.global

import akka.actor.Props
import akka.actor.{ ActorSystem, Actor, ActorRef}
import akka.pattern.{ ask, pipe }
import akka.util.Timeout

import akka.testkit.{ ImplicitSender, TestActors, TestKit }
import org.scalatest.{ BeforeAndAfterAll, Matchers, WordSpecLike }

case class ClientHello()
case class ServerHello()
case class ClientAccept(s: ServerHello)
case class ServerAccept(a: ClientAccept)
case class SharedSecret(s: ServerAccept)

class NonProtocolConformingMessage extends Exception

object Handshake {

  implicit val timeout = Timeout(5 seconds) // needed for `?` below

  def initiateHandshake (server: ActorRef): Future[SharedSecret] =
    for {
      hello <- (server ask ClientHello()).mapTo[ServerHello]
      accept <- (server ask ClientAccept(hello)).mapTo[ServerAccept]
    } yield SharedSecret(accept)

}

class Server extends Actor {

  implicit val timeout = Timeout(5 seconds) // needed for `?` below

  def receive = {
    case hello: ClientHello => {
      sender() ! ServerHello()//.mapTo[ClientAccept]
    }
    case accept: ClientAccept => {
      sender() ! ServerAccept(accept)
    }
    case _      => throw new Exception("Server can't read message")
  }
}



class HandshakeSpec
    extends TestKit(ActorSystem("MySpec"))
    with ImplicitSender
    with WordSpecLike
    with Matchers
    with BeforeAndAfterAll {

  override def afterAll {
    TestKit.shutdownActorSystem(system)
  }

  "Object.initiateHandshake" must {

    "return a Future[SharedSecret] with a cooperative server" in {
      val server = system.actorOf(Props[Server])
      val f = Handshake.initiateHandshake(server)
      val ss: SharedSecret = Await
        .result(f, 3 seconds)
        .asInstanceOf[SharedSecret]

      ss shouldBe a [SharedSecret]
      ss.s shouldBe a [ServerAccept]
      ss.s.a shouldBe a [ClientAccept]
    }



    // TODO Uncooperative partners
    // TODO To complete the future with an exception you need to send an
    // akka.actor.Status.Failure message to the sender. This is not done
    // automatically when an actor throws an exception while processing a
    // message.

  }
}
