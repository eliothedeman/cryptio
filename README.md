[![CircleCI](https://circleci.com/gh/eliothedeman/cryptio.svg?style=svg)](https://circleci.com/gh/eliothedeman/cryptio)
[![Go Report Card](https://goreportcard.com/badge/github.com/eliothedeman/cryptio)](https://goreportcard.com/report/github.com/eliothedeman/cryptio)
[![GoDoc](https://godoc.org/github.com/eliothedeman/cryptio?status.svg)](https://godoc.org/github.com/eliothedeman/cryptio)

# cryptio
Crypto wrappers around Go's io package interfaces


## Currently supported interfaces
* ReadWriteSeeker
  * Allows for the transparent encryption of a file in go using a generic crypto.Block cipher and an io.ReadWriteSeeker.