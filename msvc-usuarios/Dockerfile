# Usar una imagen base de OpenJDK 17
FROM openjdk:17-jdk-slim

# Establecer el directorio de trabajo
WORKDIR /app

# Instalar wget para descargar dockerize
RUN apt-get update && apt-get install -y wget && rm -rf /var/lib/apt/lists/*

# Descargar dockerize
RUN wget https://github.com/jwilder/dockerize/releases/download/v0.6.1/dockerize-linux-amd64-v0.6.1.tar.gz \
    && tar -C /usr/local/bin -xzvf dockerize-linux-amd64-v0.6.1.tar.gz \
    && rm dockerize-linux-amd64-v0.6.1.tar.gz

# Copiar el JAR generado al contenedor
COPY target/msvc-usuarios-1.0-SNAPSHOT.jar /app/msvc-usuarios-1.0-SNAPSHOT.jar

# Comando para ejecutar el JAR con dockerize
ENTRYPOINT ["dockerize", "-wait", "tcp://mysql:3306/appdb", "-wait", "tcp://security-service:9000", "-timeout", "60s", "java", "-jar", "/app/msvc-usuarios-1.0-SNAPSHOT.jar"]

# Exponer el puerto 8001
EXPOSE 8001
