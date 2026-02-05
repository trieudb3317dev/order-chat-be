
# Multi-stage build: build the jar with Maven, then produce a small runtime image
FROM maven:3.9.4-eclipse-temurin-17 AS builder
WORKDIR /build

# Copy pom and wrapper first to leverage Docker cache
COPY pom.xml mvnw ./
COPY .mvn .mvn

# Copy source and build application
COPY src ./src
RUN mvn -B -DskipTests package

FROM eclipse-temurin:17-jdk-jammy
WORKDIR /app

# Copy the built jar from the builder stage
COPY --from=builder /build/target/*.jar /app/app.jar

EXPOSE 8008

ENTRYPOINT ["java", "-jar", "/app/app.jar"]