FROM ghcr.io/graalvm/native-image-community:latest as build
WORKDIR /workspace/app

# Copy the project files
COPY ../pom.xml ../
COPY . .

RUN --mount=type=cache,target=/root/.m2 ./mvnw clean package -DskipTests -Pnative,enhance native:compile

FROM ghcr.io/linuxcontainers/alpine:3.20

VOLUME /tmp
RUN apk add --no-cache libc6-compat

# Set the Spring profile to 'production'
ENV SPRING_PROFILES_ACTIVE=production

COPY --from=build /workspace/app/target/auth-server /app/auth-server

# Expose the application's port
EXPOSE 9000

ENTRYPOINT ["/app/auth-server"]

# CMD with dynamic port
# CMD ["sh", "-c", "/app/auth-server -Dserver.port=${PORT:-9000}"]