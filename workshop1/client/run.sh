#! /bin/bash

curl -X POST -v localhost:8080/customResponse -d '{"size": 10000}'
