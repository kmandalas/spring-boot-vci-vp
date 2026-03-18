FROM maven:3.9-eclipse-temurin-25-alpine AS build
WORKDIR /workspace/app

# Copy the project files
COPY ../pom.xml ../
COPY . .

RUN --mount=type=cache,target=/root/.m2 mvn clean package -DskipTests

FROM eclipse-temurin:25-jre-alpine

VOLUME /tmp

# Set the Spring profile to 'cloud'
ENV SPRING_PROFILES_ACTIVE=cloud

COPY --from=build /workspace/app/target/*.jar /app/qtsp-mock.jar

# Expose the application's port
EXPOSE 9003

ENTRYPOINT ["java", "-jar", "/app/qtsp-mock.jar"]
