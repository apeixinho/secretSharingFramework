FROM openjdk:17-alpine
ADD ./target/secret-sharing-api-1.0-SNAPSHOT.jar /usr/src/secret-sharing-api-1.0-SNAPSHOT.jar
WORKDIR /usr/src
ENTRYPOINT ["java","-jar", "secret-sharing-api-1.0-SNAPSHOT.jar"]