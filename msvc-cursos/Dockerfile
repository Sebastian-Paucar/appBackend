# Etapa de producción
FROM openjdk:17-jdk-slim
WORKDIR /app

# Instalar wget para descargar dockerize
RUN apt-get update && apt-get install -y wget && rm -rf /var/lib/apt/lists/*

# Descargar dockerize
RUN wget https://github.com/jwilder/dockerize/releases/download/v0.6.1/dockerize-linux-amd64-v0.6.1.tar.gz \
    && tar -C /usr/local/bin -xzvf dockerize-linux-amd64-v0.6.1.tar.gz \
    && rm dockerize-linux-amd64-v0.6.1.tar.gz

# Copiar el JAR previamente construido desde tu máquina local al contenedor
COPY target/msvc-cursos-0.0.1-SNAPSHOT.jar /app/msvc-cursos-0.0.1-SNAPSHOT.jar

# Configurar el comando de inicio para esperar a PostgreSQL y al servicio de seguridad
ENTRYPOINT ["dockerize", "-wait", "tcp://postgres:5432", "-wait", "tcp://security-service:9000", "-timeout", "60s", "java", "-jar", "/app/msvc-cursos-0.0.1-SNAPSHOT.jar"]

# Exponer el puerto del servicio
EXPOSE 8002
