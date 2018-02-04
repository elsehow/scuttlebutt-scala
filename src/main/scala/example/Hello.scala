package scuttlebutt

import scala.concurrent.Future
// the following is equivalent to `implicit val ec = ExecutionContext.global`
import scala.concurrent.ExecutionContext.Implicits.global

abstract class Message

abstract class Participant

abstract class Channel {
  // tools for reading from the channel
  /** Waits for Option[Message]. If message is None, the other participant hung
    * up, or the connection was dropped */
  def wait (message: Message): Future[Option[Message]] = ???
  // tools for writing to the channel
  /** Hang up the channel */
  def hangup: Unit = ???
  /** Write a Message to the channel and wait for Option[Message]. If message is
    None, the other participant hung up, or the connection was dropped. */
  def writeAndWait (message: Message): Future[Option[Message]] = ???
  /** Write a Message to the channel and hang up immediately */
  def writeAndHangup (message: Message): Unit = ???
}

abstract class Protocol (
  messages: Vector[(Participant, Message)]
) {
  type T
  def begin (channel: Channel): Future[Option[T]] = ???
}
