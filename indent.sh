#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
pushd $DIR
emacs --batch --script indent.el
popd
