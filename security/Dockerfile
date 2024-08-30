# security/Dockerfile
# Utiliza una imagen base de OpenJDK 17
FROM openjdk:17-jdk-slim

# Establece el directorio de trabajo
WORKDIR /app

# Copia el JAR generado al contenedor
COPY target/security-1.0.0-SNAPSHOT.jar /app/security-1.0.0-SNAPSHOT.jar

# Comando para ejecutar el JAR
ENTRYPOINT ["java", "-jar", "/app/security-1.0.0-SNAPSHOT.jar"]

# Expone el puerto 9000
EXPOSE 9000
