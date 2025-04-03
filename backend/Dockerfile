FROM openjdk:21-slim
ADD ./target/secret-sharing-api-1.0-SNAPSHOT.jar /usr/src/secret-sharing-api-1.0-SNAPSHOT.jar
WORKDIR /usr/src
ENTRYPOINT ["java","-jar", "secret-sharing-api-1.0-SNAPSHOT.jar"]