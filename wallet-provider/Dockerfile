FROM ghcr.io/graalvm/native-image-community:latest as build
WORKDIR /workspace/app

# Copy the project files
COPY ../pom.xml ../
COPY . .

RUN --mount=type=cache,target=/root/.m2 ./mvnw clean package -DskipTests -Pnative,enhance native:compile

FROM ghcr.io/linuxcontainers/alpine:3.20

VOLUME /tmp
RUN apk add --no-cache libc6-compat

# Set the Spring profile to 'cloud'
ENV SPRING_PROFILES_ACTIVE=cloud

COPY --from=build /workspace/app/target/wallet-provider /app/wallet-provider

# Expose the application's port
EXPOSE 9001

ENTRYPOINT ["/app/wallet-provider"]
