#!/bin/sh

grep -rl $1 | xargs sed -i "s/\<$1\>/$2/g"
