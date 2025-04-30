# Use an official Go runtime as a parent image
FROM golang:1.23-alpine AS builder

# Set the working directory
WORKDIR /app

# Copy the Go module files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the source code
COPY *.go ./

# Build the Go app - static build recommended for alpine
# CGO_ENABLED=0 prevents use of C libraries (like glibc)
# -ldflags="-w -s" reduces binary size
RUN CGO_ENABLED=0 go build -ldflags="-w -s" -o /ldap-to-vcf .

# Use a minimal base image
FROM alpine:latest

# Install ca-certificates for TLS verification
RUN apk --no-cache add ca-certificates

# Set the working directory
WORKDIR /app

# Copy the built executable from the builder stage
COPY --from=builder /ldap-to-vcf /app/ldap-to-vcf

# RUN addgroup -S appgroup && adduser -S appuser -G appgroup
# USER appuser

# Expose port if needed (not typical for this kind of tool)
# EXPOSE 8080

# Define environment variables (can be overridden at runtime)
# Set defaults or leave empty to require runtime configuration
ENV LDAP_URL="" \
    LDAP_BIND_DN="" \
    LDAP_BIND_PASSWORD="" \
    LDAP_BASE_DN="" \
    LDAP_SEARCH_FILTER="(objectClass=inetOrgPerson)" \
    LDAP_ATTRIBUTE_MAPPING="FN:cn,N:sn;givenName,EMAIL;TYPE=work:mail,TEL;TYPE=work:telephoneNumber" \
    VCF_OUTPUT_FILE="/data/contacts.vcf" \
    CRON_SCHEDULE="" \
    LDAP_USE_TLS="false" \
    LDAP_SKIP_TLS_VERIFY="false"

# Command to run the executable
CMD ["/app/ldap-to-vcf"]

