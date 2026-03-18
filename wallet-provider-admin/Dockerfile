FROM eclipse-temurin:25-jdk-alpine AS build
WORKDIR /workspace/app

# Copy the project files
COPY ../pom.xml ../
COPY . .

RUN --mount=type=cache,target=/root/.m2 ./mvnw clean package -DskipTests

FROM eclipse-temurin:25-jre-alpine

VOLUME /tmp

# Set the Spring profile to 'cloud'
ENV SPRING_PROFILES_ACTIVE=cloud

COPY --from=build /workspace/app/target/*.jar /app/wallet-provider-admin.jar

# Expose the application's port
EXPOSE 9004

ENTRYPOINT ["java", "-jar", "/app/wallet-provider-admin.jar"]
