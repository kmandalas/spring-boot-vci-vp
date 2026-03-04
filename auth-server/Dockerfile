FROM eclipse-temurin:21-jdk as build
WORKDIR /workspace/app

# Copy the project files
COPY ../pom.xml ../
COPY . .

RUN --mount=type=cache,target=/root/.m2 ./mvnw clean package -DskipTests

FROM eclipse-temurin:21-jre

VOLUME /tmp

# Set the Spring profile to 'cloud'
ENV SPRING_PROFILES_ACTIVE=cloud

COPY --from=build /workspace/app/target/*.jar /app/auth-server.jar

# Expose the application's port
EXPOSE 9000

ENTRYPOINT ["java", "-jar", "/app/auth-server.jar"]
