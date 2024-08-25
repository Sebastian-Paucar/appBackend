# msvc-cursos/Dockerfile
FROM maven:3.8.5-openjdk-17 AS build
WORKDIR /app
COPY . /app
RUN mvn clean package -DskipTests

FROM openjdk:17-jdk-slim
WORKDIR /app
COPY --from=build /app/target/msvc-cursos-0.0.1-SNAPSHOT.jar /app/msvc-cursos-0.0.1-SNAPSHOT.jar
ENTRYPOINT ["java", "-jar", "/app/msvc-cursos-0.0.1-SNAPSHOT.jar"]

EXPOSE 8002
