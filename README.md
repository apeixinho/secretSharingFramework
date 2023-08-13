# Secret Sharing API

## Implementation using Springboot

[Docker](https://www.docker.com/) and 
[docker compose](https://docs.docker.com/compose/) are required to build and run the application containerized 

## Docker / Compose

In the project root folder, in order to build the image, from which the container will be instantied, execute the following command:

```
docker compose build
# or 
docker build . -t <image name>
```

To instantiate a container, in detached mode, based from that image, execute the following command:

```
docker compose up -d
# or 
docker run -d <image name>

```

To view and follow the logs, being output by the application, execute the following command:
```
docker compose logs -f
# or 
docker logs -f <container name>

```


After starting the application, documentation and testing are available at: [localhost:8080/swagger-ui.html](http://localhost:8080/swagger-ui.html)


To debug a running container and get a shell, bash, zsh, etc, in the container, execute the following command:

```
docker exec -it <container name> bash

```

To debug a running container, or execute a command, in the container, execute the following command:

```
docker exec <container name> command
# to run a shell, or execute the command of a shell, like bash, zsh, etc

```