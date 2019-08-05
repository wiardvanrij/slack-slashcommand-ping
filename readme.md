# A slash command for Slack in Golang, running in a container on kubernetes

## Why

Because I wanted to create a slash command and distribute it. 

Initialy I wanted to run this as a cloud function within GKE, but due to limitataion (ICMP not allowed) this was not possible

## Workings

- This code includes the oauth implemenation required for distrubution. 
- It has the correct requirements, such as error handling, signing, etc
- It runs in a docker container on kubernetes


## More info...

I will create a blog later on. For now people can read the code on "how it works". It requires some basic knowledge of the Slack API and Golang.
