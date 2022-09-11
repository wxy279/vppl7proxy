#!/bin/bash

grep -lr "\<$1\>" ./ | xargs sed -i "s/\<$1\>/$2/g"
