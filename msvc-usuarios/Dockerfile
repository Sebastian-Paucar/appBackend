# msvc-usuarios/Dockerfile
FROM maven:3.8.5-openjdk-17 AS build
WORKDIR /app
COPY . /app
RUN mvn clean package -DskipTests

FROM openjdk:17-jdk-slim
WORKDIR /app
COPY --from=build /app/target/msvc-usuarios-1.0-SNAPSHOT.jar /app/msvc-usuarios-1.0-SNAPSHOT.jar
ENTRYPOINT ["java", "-jar", "/app/msvc-usuarios-1.0-SNAPSHOT.jar"]

EXPOSE 8001
