FROM eclipse-temurin:21-jdk-alpine

WORKDIR /app

COPY .mvn/ .mvn
COPY mvnw pom.xml ./
RUN chmod +x mvnw && sed -i 's/\r$//' mvnw \
	&& ./mvnw dependency:resolve

COPY src ./src

CMD ["./mvnw", "spring-boot:run"]
