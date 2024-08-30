# Spring Boot Application Deployment

This repository contains the Spring Boot application code and the necessary configuration to deploy it on a Google Compute Engine (GCE) instance created by the infrastructure repository.

## Key Components

1. **GitHub Actions**: 
   - Used to check out the repository and build the JAR package for the Spring Boot application.
   - Automates the build and deployment process.

2. **Ansible**: 
   - Configures the GCE instance created by the infra repository.
   - Installs necessary modules on the GCE instance.
   - Writes the `devops.sql` file to the SQL database server created in the infra repository.
   - Copies the JAR file to the GCE server and runs it as a service.

3. **Secret Management**:
   - Secrets, including the `ssh_key` used to authenticate to the GCE instance, are stored securely as GitHub secrets and Terraform Cloud variables.
   - For production environments, more advanced secret management solutions like HashiCorp Vault, CyberArk Conjur, or Google Secret Manager can be used.

## Major Purpose of This Repository

- **Configure the GCE instance**: Set up and prepare the GCE instance for running the Spring Boot application.
- **Configure the SQL Database**: Execute SQL commands in the `devops.sql` file to set up the database, which was created by the infrastructure repository.

This repository is an essential part of the overall deployment pipeline, focusing on the application layer and server configuration.
