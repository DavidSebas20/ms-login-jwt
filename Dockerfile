# Use the official Golang image as the base image
FROM golang:1.21-alpine

# Set the working directory inside the container
WORKDIR /app

# Copy go.mod and go.sum files to download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the application source code
COPY . .

# Build the application
RUN go build -o jwt-service

# Command to run the application
CMD ["./jwt-service"]
