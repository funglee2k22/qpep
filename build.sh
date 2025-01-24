#!/bin/bash

go clean -cache -x

pushd backend
rm -rf quicly-go/internal/deps/lib
rm -rf quicly-go/internal/deps/bin

go generate
popd

rm build/qpep

go build -v -o build/qpep
