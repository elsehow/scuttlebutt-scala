import Dependencies._

lazy val root = (project in file(".")).
  settings(
    inThisBuild(List(
      organization := "com.example",
      scalaVersion := "2.12.4",
      version      := "0.1.0-SNAPSHOT"
    )),
    name := "Hello",
    libraryDependencies ++= Seq(
      scalaTest % Test,
      "com.typesafe.akka" %% "akka-actor" % "2.5.9",
      "com.typesafe.akka" %% "akka-testkit" % "2.5.9" % Test,
      "org.abstractj.kalium" % "kalium" %	"0.7.0"
    )
  )
