# ZATCA Phase 2 API - Administration Guide

## Table of Contents

1. [Introduction](#introduction)
2. [System Overview](#system-overview)
3. [Installation & Deployment](#installation--deployment)
4. [Configuration Management](#configuration-management)
5. [User Management](#user-management)
6. [Device Management](#device-management)
7. [Certificate Management](#certificate-management)
8. [Monitoring & Maintenance](#monitoring--maintenance)
9. [Troubleshooting](#troubleshooting)
10. [Backup & Recovery](#backup--recovery)
11. [Security Best Practices](#security-best-practices)
12. [Appendices](#appendices)

---

## 1. Introduction

### Purpose

This administration guide provides detailed information for system administrators to install, configure, manage, and maintain the ZATCA Phase 2 API system. The guide covers all aspects of administration, from initial deployment to ongoing maintenance and troubleshooting.

### Audience

This guide is intended for:
- System Administrators
- Database Administrators
- Security Officers
- IT Operations staff responsible for maintaining the ZATCA e-invoicing system

### Scope

This guide covers:
- Installation and deployment procedures
- Configuration management
- User administration
- Device and certificate management
- System monitoring and maintenance
- Troubleshooting common issues
- Security best practices
- Backup and recovery procedures

---

## 2. System Overview

### Architecture

The ZATCA Phase 2 API system consists of several components:

1. **Web API Layer**: ASP.NET Core Web API providing RESTful endpoints
2. **Service Layer**: Business logic and integration with ZATCA
3. **Data Access Layer**: Database interaction using Entity Framework Core
4. **Database**: SQL Server database storing users, devices, certificates, and invoice reports
5. **Certificate Store**: Secure storage for digital certificates and private keys

![System Architecture](https://example.com/architecture-diagram.png)

### System Requirements

#### Hardware Requirements

- **Production Environment**:
  - CPU: 4+ cores
  - RAM: 16+ GB
  - Storage: 100+ GB SSD (depending on transaction volume)
  - Network: 100+ Mbps internet connection

- **Development/Testing Environment**:
  - CPU: 2+ cores
  - RAM: 8+ GB
  - Storage: 50+ GB SSD
  - Network: 10+ Mbps internet connection

#### Software Requirements

- **Operating System**: Windows Server 2019/2022 or Linux (Ubuntu 20.04+)
- **Web Server**: IIS 10+ (Windows) or Nginx/Apache (Linux)
- **Database**: SQL Server 2019+ or SQL Server Express
- **Runtime**: .NET Core 6.0+ Runtime and SDK
- **SSL Certificate**: Valid SSL certificate for HTTPS

#### Network Requirements

- Outbound access to ZATCA API endpoints (ports 443/80)
- Firewall rules allowing the application to communicate with ZATCA services
- DNS resolution for ZATCA domains

---

## 3. Installation & Deployment

### Pre-Installation Checklist

- [ ] Verify system meets hardware and software requirements
- [ ] Ensure database server is installed and accessible
- [ ] Verify network connectivity to ZATCA API endpoints
- [ ] Confirm SSL certificate is available for secure communication
- [ ] Ensure administrator has necessary permissions for installation

### Installation Steps

#### Windows Server Installation

1. **Install Prerequisites**:
   ```powershell
   # Install IIS
   Install-WindowsFeature -name Web-Server -IncludeManagementTools

   # Install .NET Core Hosting Bundle
   # Download from https://dotnet.microsoft.com/download/dotnet/6.0
   ```

2. **Deploy the Application**:
   ```powershell
   # Create application directory
   New-Item -ItemType Directory -Path "C:\zatca-api"
   
   # Extract application files to the directory
   Expand-Archive -Path "zatca-api.zip" -DestinationPath "C:\zatca-api"
   ```

3. **Configure IIS**:
   ```powershell
   # Create IIS application pool
   New-WebAppPool -Name "ZatcaApiPool" -Force
   Set-ItemProperty -Path "IIS:\AppPools\ZatcaApiPool" -Name "managedRuntimeVersion" -Value ""
   
   # Create IIS website
   New-Website -Name "ZatcaApi" -PhysicalPath "C:\zatca-api" -ApplicationPool "ZatcaApiPool" -Port 443 -Force
   ```

4. **Set Up Database**:
   ```powershell
   # Run database migration
   cd C:\zatca-api
   dotnet ef database update
   ```

#### Linux Server Installation

1. **Install Prerequisites**:
   ```bash
   # Install .NET Core SDK
   wget https://packages.microsoft.com/config/ubuntu/20.04/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
   sudo dpkg -i packages-microsoft-prod.deb
   sudo apt-get update
   sudo apt-get install -y apt-transport-https
   sudo apt-get install -y dotnet-sdk-6.0
   
   # Install Nginx
   sudo apt-get install -y nginx
   ```

2. **Deploy the Application**:
   ```bash
   # Create application directory
   sudo mkdir -p /var/www/zatca-api
   
   # Extract application files
   sudo unzip zatca-api.zip -d /var/www/zatca-api
   ```

3. **Configure Nginx**:
   ```bash
   # Create Nginx configuration file
   sudo nano /etc/nginx/sites-available/zatca-api
   
   # Add the following configuration
   server {
       listen 443 ssl;
       server_name your-domain.com;
       
       ssl_certificate /path/to/certificate.crt;
       ssl_certificate_key /path/to/private.key;
       
       location / {
           proxy_pass http://localhost:5000;
           proxy_http_version 1.1;
           proxy_set_header Upgrade $http_upgrade;
           proxy_set_header Connection keep-alive;
           proxy_set_header Host $host;
           proxy_cache_bypass $http_upgrade;
       }
   }
   
   # Enable the site
   sudo ln -s /etc/nginx/sites-available/zatca-api /etc/nginx/sites-enabled/
   sudo nginx -t
   sudo systemctl reload nginx
   ```

4. **Set Up the Service**:
   ```bash
   # Create service file
   sudo nano /etc/systemd/system/zatca-api.service
   
   # Add the following content
   [Unit]
   Description=ZATCA Phase 2 API
   
   [Service]
   WorkingDirectory=/var/www/zatca-api
   ExecStart=/usr/bin/dotnet /var/www/zatca-api/ZatcaPhase2Api.dll
   Restart=always
   RestartSec=10
   SyslogIdentifier=zatca-api
   User=www-data
   Environment=ASPNETCORE_ENVIRONMENT=Production
   
   [Install]
   WantedBy=multi-user.target
   
   # Enable and start the service
   sudo systemctl enable zatca-api
   sudo systemctl start zatca-api
   ```

5. **Set Up Database**:
   ```bash
   # Run database migration
   cd /var/www/zatca-api
   dotnet ef database update
   ```

### Container Deployment (Docker)

1. **Create Dockerfile**:
   ```dockerfile
   FROM mcr.microsoft.com/dotnet/aspnet:6.0 AS base
   WORKDIR /app
   EXPOSE 80
   EXPOSE 443
   
   FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build
   WORKDIR /src
   COPY ["ZatcaPhase2Api.csproj", "./"]
   RUN dotnet restore "ZatcaPhase2Api.csproj"
   COPY . .
   RUN dotnet build "ZatcaPhase2Api.csproj" -c Release -o /app/build
   
   FROM build AS publish
   RUN dotnet publish "ZatcaPhase2Api.csproj" -c Release -o /app/publish
   
   FROM base AS final
   WORKDIR /app
   COPY --from=publish /app/publish .
   ENTRYPOINT ["dotnet", "ZatcaPhase2Api.dll"]
   ```

2. **Build and Run Container**:
   ```bash
   # Build the Docker image
   docker build -t zatca-api .
   
   # Run the container
   docker run -d -p 443:443 --name zatca-api-container zatca-api
   ```

3. **Docker Compose Setup**:
   ```yaml
   version: '3.8'
   
   services:
     api:
       build: .
       ports:
         - "443:443"
       environment:
         - ASPNETCORE_ENVIRONMENT=Production
         - ConnectionStrings__DefaultConnection=Server=db;Database=ZatcaPhase2;User=sa;Password=YourPassword;
       depends_on:
         - db
       volumes:
         - ./certs:/app/certs
   
     db:
       image: mcr.microsoft.com/mssql/server:2019-latest
       environment:
         - ACCEPT_EULA=Y
         - SA_PASSWORD=YourPassword
       ports:
         - "1433:1433"
       volumes:
         - zatca-db-data:/var/opt/mssql
   
   volumes:
     zatca-db-data:
   ```

### Post-Installation Verification

1. **Verify API Accessibility**:
   ```bash
   # Test API health check endpoint
   curl -k https://your-domain.com/api/health
   
   # Should return a success response
   ```

2. **Verify Database Connection**:
   - Check application logs for database connection errors
   - Run a simple database query to ensure connectivity

3. **Verify ZATCA Connectivity**:
   - Test connection to ZATCA endpoints
   - Check for network-related errors in logs

---

## 4. Configuration Management

### Configuration Files

The primary configuration file is `appsettings.json` located in the application root directory. This file contains database connection strings, JWT settings, ZATCA API endpoints, and other application settings.

#### Sample Configuration

```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Server=localhost;Database=ZatcaPhase2;User=sa;Password=YourPassword;MultipleActiveResultSets=true"
  },
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft": "Warning",
      "Microsoft.Hosting.Lifetime": "Information"
    }
  },
  "AllowedHosts": "*",
  "Jwt": {
    "Key": "your_secure_key_here_at_least_32_characters_long",
    "Issuer": "your_issuer",
    "Audience": "your_audience",
    "ExpiryMinutes": 60
  },
  "ZatcaApi": {
    "BaseUrl": "https://gw-fatoora-zatca-sandbox.portal.gov.sa/",
    "ComplianceCsrEndpoint": "compliance",
    "ProductionCsrEndpoint": "production",
    "ClearanceEndpoint": "clearance",
    "ReportingEndpoint": "reporting",
    "ComplianceCheckEndpoint": "compliance/check",
    "ClearedInvoiceEndpoint": "clearance/invoice"
  },
  "Environment": "Sandbox",
  "CertificateSettings": {
    "StorePath": "/path/to/certificate/store",
    "PasswordProtection": true
  }
}
```

### Environment-Specific Configuration

For different environments (development, staging, production), use environment-specific configuration files:
- `appsettings.Development.json`
- `appsettings.Staging.json`
- `appsettings.Production.json`

### Configuration Parameters

| Parameter | Description | Default Value |
|-----------|-------------|---------------|
| ConnectionStrings:DefaultConnection | Database connection string | - |
| Jwt:Key | Secret key for JWT token signing | - |
| Jwt:Issuer | JWT token issuer | - |
| Jwt:Audience | JWT token audience | - |
| Jwt:ExpiryMinutes | JWT token expiry in minutes | 60 |
| ZatcaApi:BaseUrl | Base URL for ZATCA API | Sandbox URL |
| ZatcaApi:ComplianceCsrEndpoint | Endpoint for compliance certificate requests | "compliance" |
| ZatcaApi:ProductionCsrEndpoint | Endpoint for production certificate requests | "production" |
| ZatcaApi:ClearanceEndpoint | Endpoint for invoice clearance | "clearance" |
| ZatcaApi:ReportingEndpoint | Endpoint for invoice reporting | "reporting" |
| Environment | Current environment (Sandbox/Production) | "Sandbox" |
| CertificateSettings:StorePath | Path to certificate store | - |
| CertificateSettings:PasswordProtection | Whether certificates are password-protected | true |

### Updating Configuration

1. **Manual Update**:
   - Edit the appropriate `appsettings.json` file
   - Restart the application to apply changes

2. **Command Line Update**:
   ```bash
   # Set configuration value via command line
   dotnet run --environment=Production --ConnectionStrings:DefaultConnection="Server=newserver;Database=ZatcaPhase2;User=sa;Password=NewPassword;"
   ```

3. **Environment Variables**:
   ```bash
   # Windows
   setx ASPNETCORE_ENVIRONMENT "Production"
   setx ConnectionStrings__DefaultConnection "Server=newserver;Database=ZatcaPhase2;User=sa;Password=NewPassword;"
   
   # Linux
   export ASPNETCORE_ENVIRONMENT="Production"
   export ConnectionStrings__DefaultConnection="Server=newserver;Database=ZatcaPhase2;User=sa;Password=NewPassword;"
   ```

### Switching Between Sandbox and Production

To switch between ZATCA sandbox and production environments:

1. Update the `ZatcaApi:BaseUrl` setting to the appropriate URL:
   - Sandbox: `https://gw-fatoora-zatca-sandbox.portal.gov.sa/`
   - Production: `https://gw-fatoora.zatca.gov.sa/`

2. Update the `Environment` setting to either "Sandbox" or "Production"

3. Restart the application to apply changes

4. Ensure appropriate certificates are obtained for the target environment

---

## 5. User Management

### User Roles

The system supports the following user roles:

1. **Admin**: Full system access, including user management and device administration
2. **User**: Regular user with access to invoice operations
3. **ApiClient**: Limited access for programmatic API usage

### Creating Admin User

To create the initial admin user:

1. **Using API Endpoint**:
   ```bash
   # Create admin user with curl
   curl -X POST -H "Content-Type: application/json" -d '{
     "username": "admin",
     "password": "StrongPassword123!",
     "email": "admin@example.com",
     "companyName": "Company Name",
     "vatRegistrationNumber": "123456789012345",
     "role": "Admin"
   }' https://your-domain.com/api/auth/register-admin
   ```

2. **Using Database Script**:
   ```sql
   -- Generate password hash
   DECLARE @PasswordHash NVARCHAR(100) = CONVERT(NVARCHAR(100), HASHBYTES('SHA2_256', 'StrongPassword123!'), 2);
   
   -- Insert admin user
   INSERT INTO Users (Username, PasswordHash, Email, CompanyName, VatRegistrationNumber, Role)
   VALUES ('admin', @PasswordHash, 'admin@example.com', 'Company Name', '123456789012345', 0);
   ```

### Managing Users

#### Adding New Users

Admins can add new users through the API:

```bash
# Create new user with curl
curl -X POST -H "Content-Type: application/json" -H "Authorization: Bearer {admin_token}" -d '{
  "username": "user1",
  "password": "StrongPassword123!",
  "email": "user1@example.com",
  "companyName": "Company Name",
  "vatRegistrationNumber": "123456789012345",
  "role": "User"
}' https://your-domain.com/api/auth/register
```

#### Modifying Users

```bash
# Update user with curl
curl -X PUT -H "Content-Type: application/json" -H "Authorization: Bearer {admin_token}" -d '{
  "email": "new-email@example.com",
  "companyName": "New Company Name",
  "vatRegistrationNumber": "123456789012345",
  "role": "User"
}' https://your-domain.com/api/users/{username}
```

#### Deleting Users

```bash
# Delete user with curl
curl -X DELETE -H "Authorization: Bearer {admin_token}" https://your-domain.com/api/users/{username}
```

#### Resetting Passwords

1. **Admin Reset**:
   ```bash
   # Reset user password with curl
   curl -X POST -H "Content-Type: application/json" -H "Authorization: Bearer {admin_token}" -d '{
     "newPassword": "NewStrongPassword123!"
   }' https://your-domain.com/api/users/{username}/reset-password
   ```

2. **Self Reset** (requires email setup):
   ```bash
   # Request password reset token
   curl -X POST -H "Content-Type: application/json" -d '{
     "username": "user1",
     "email": "user1@example.com"
   }' https://your-domain.com/api/auth/forgot-password
   
   # Reset password with token
   curl -X POST -H "Content-Type: application/json" -d '{
     "token": "reset-token",
     "newPassword": "NewStrongPassword123!"
   }' https://your-domain.com/api/auth/reset-password
   ```

### Security Policies

Implement the following security policies for user management:

1. **Password Policy**:
   - Minimum length: 12 characters
   - Require combination of uppercase, lowercase, numbers, and special characters
   - Enforce password expiry (90 days recommended)
   - Prevent password reuse (last 5 passwords)

2. **Account Lockout**:
   - Lock account after 5 failed login attempts
   - Require administrator reset for locked accounts
   - Implement progressive delays between login attempts

3. **Session Management**:
   - Set reasonable token expiry (60 minutes recommended)
   - Implement token refresh mechanism
   - Force logout on suspicious activity

---

## 6. Device Management

### Device Registration Process

1. **Register Device**:
   ```bash
   # Register device with curl
   curl -X POST -H "Content-Type: application/json" -H "Authorization: Bearer {token}" -d '{
     "deviceSerialNumber": "POS123456",
     "deviceName": "Test POS",
     "model": "Model X1",
     "hardwareVersion": "1.0",
     "softwareVersion": "1.0",
     "vatRegistrationNumber": "123456789012345",
     "companyName": "Test Company LLC",
     "commercialRegistrationNumber": "1234567890",
     "streetName": "King Fahd Road",
     "buildingNumber": "1234",
     "cityName": "Riyadh",
     "districtName": "Al Olaya",
     "postalCode": "12345",
     "countryCode": "SA",
     "certificateType": "Compliance"
   }' https://your-domain.com/api/devices/register
   ```

2. **Generate CSR**:
   ```bash
   # Generate CSR with curl
   curl -X POST -H "Authorization: Bearer {token}" https://your-domain.com/api/devices/POS123456/generatecsr
   ```

3. **Request Compliance Certificate**:
   ```bash
   # Request compliance certificate with curl
   curl -X POST -H "Authorization: Bearer {token}" https://your-domain.com/api/devices/POS123456/compliancecertificate
   ```

4. **Request Production Certificate** (after obtaining OTP from ZATCA portal):
   ```bash
   # Request production certificate with curl
   curl -X POST -H "Content-Type: application/json" -H "Authorization: Bearer {token}" -d '"123456"' https://your-domain.com/api/devices/POS123456/productioncertificate
   ```

### Device Status Management

Devices can have the following statuses:
1. **Pending**: Initial state after registration
2. **Registered**: Device has a compliance certificate
3. **Active**: Device has a production certificate and is ready for use
4. **Suspended**: Device has been temporarily suspended
5. **Deactivated**: Device has been permanently deactivated

To update device status:

```bash
# Update device status with curl
curl -X PUT -H "Content-Type: application/json" -H "Authorization: Bearer {token}" -d '2' https://your-domain.com/api/devices/POS123456/status
```

### Listing Devices

```bash
# List all devices with curl
curl -H "Authorization: Bearer {token}" https://your-domain.com/api/devices
```

### Viewing Device Details

```bash
# Get device details with curl
curl -H "Authorization: Bearer {token}" https://your-domain.com/api/devices/POS123456
```

### Device Certificate Information

```bash
# Get certificate details with curl
curl -H "Authorization: Bearer {token}" https://your-domain.com/api/devices/POS123456/certificate
```

---

## 7. Certificate Management

### Certificate Lifecycle

ZATCA certificates go through the following lifecycle:

1. **CSR Generation**: System generates a Certificate Signing Request (CSR)
2. **Compliance Certificate**: Initial certificate for testing and onboarding
3. **Production Certificate**: Certificate for production use (requires OTP)
4. **Certificate Renewal**: Process to renew certificates before expiry
5. **Certificate Revocation**: Process to revoke compromised certificates

### Monitoring Certificate Expiry

Certificates have the following validity periods:
- Compliance Certificates: 1 year
- Production Certificates: 3 years

To monitor certificate expiration:

1. **Using API Endpoint**:
   ```bash
   # Get expiring certificates with curl
   curl -H "Authorization: Bearer {token}" https://your-domain.com/api/admin/certificates/expiring
   ```

2. **Using Database Query**:
   ```sql
   -- Find certificates expiring in the next 30 days
   SELECT DeviceSerialNumber, CertificateExpiryDate
   FROM Devices
   WHERE CertificateExpiryDate IS NOT NULL
   AND CertificateExpiryDate BETWEEN GETDATE() AND DATEADD(DAY, 30, GETDATE())
   ORDER BY CertificateExpiryDate;
   ```

### Certificate Renewal Process

To renew a certificate before expiry:

1. **Generate New CSR**:
   ```bash
   # Generate new CSR with curl
   curl -X POST -H "Authorization: Bearer {token}" https://your-domain.com/api/devices/POS123456/renewcertificate
   ```

2. **For Compliance Certificates**:
   ```bash
   # Request new compliance certificate with curl
   curl -X POST -H "Authorization: Bearer {token}" https://your-domain.com/api/devices/POS123456/compliancecertificate
   ```

3. **For Production Certificates** (requires new OTP from ZATCA portal):
   ```bash
   # Request new production certificate with curl
   curl -X POST -H "Content-Type: application/json" -H "Authorization: Bearer {token}" -d '"123456"' https://your-domain.com/api/devices/POS123456/productioncertificate
   ```

### Secure Certificate Storage

Certificates and private keys should be stored securely:

1. **Database Storage**:
   - Store certificates and keys in encrypted format
   - Use column-level encryption for certificate data
   - Restrict access to certificate tables

2. **File System Storage**:
   - Store certificates in protected directories
   - Use proper file permissions (600 or more restrictive)
   - Consider hardware security modules (HSMs) for production environments

3. **Certificate Password Protection**:
   - Use strong passwords for certificate files
   - Store passwords in a secure password manager
   - Rotate passwords regularly

---

## 8. Monitoring & Maintenance

### Logging Configuration

The system uses structured logging with Serilog. Configure logging in `appsettings.json`:

```json
"Logging": {
  "LogLevel": {
    "Default": "Information",
    "Microsoft": "Warning",
    "Microsoft.Hosting.Lifetime": "Information"
  },
  "Serilog": {
    "MinimumLevel": {
      "Default": "Information",
      "Override": {
        "Microsoft": "Warning",
        "System": "Warning"
      }
    },
    "WriteTo": [
      {
        "Name": "File",
        "Args": {
          "path": "logs/zatca-api-.log",
          "rollingInterval": "Day",
          "retainedFileCountLimit": 30,
          "formatter": "Serilog.Formatting.Json.JsonFormatter"
        }
      },
      {
        "Name": "Console",
        "Args": {
          "theme": "Serilog.Sinks.SystemConsole.Themes.AnsiConsoleTheme::Code"
        }
      }
    ],
    "Enrich": ["FromLogContext", "WithMachineName", "WithThreadId"]
  }
}
```

### Log Monitoring

1. **Log File Location**:
   - Windows: `C:\zatca-api\logs\`
   - Linux: `/var/www/zatca-api/logs/`
   - Docker: `/app/logs/` (mount as volume)

2. **Important Log Events to Monitor**:
   - Certificate operations (generation, renewal, expiry)
   - Failed invoice submissions
   - Authentication failures
   - API errors when communicating with ZATCA

3. **Log Analysis Tools**:
   - Use ELK Stack (Elasticsearch, Logstash, Kibana) for centralized logging
   - Set up alerts for critical error patterns
   - Implement log rotation to manage disk space

### Performance Monitoring

1. **Key Metrics to Monitor**:
   - API response times
   - Database query performance
   - Memory usage
   - CPU utilization
   - Disk space
   - Network connectivity to ZATCA

2. **Monitoring Tools**:
   - Application Insights for application performance
   - Prometheus for metrics collection
   - Grafana for visualization
   - SQL Server monitoring tools for database performance

3. **Setting Up Alerts**:
   - Configure alerts for critical thresholds
   - Set up notification channels (email, SMS, Slack)
   - Implement escalation procedures

### Database Maintenance

1. **Regular Tasks**:
   - Index maintenance (weekly)
   - Statistics updates (daily)
   - Database backups (daily full, hourly differential)
   - Log file management (weekly)

2. **SQL Maintenance Script**:
   ```sql
   -- Update statistics
   EXEC sp_updatestats;
   
   -- Rebuild indexes with fragmentation > 30%
   DECLARE @TableName NVARCHAR(255)
   DECLARE @cmd NVARCHAR(500)
   DECLARE @fillfactor INT
   SET @fillfactor = 90
   
   DECLARE TableCursor CURSOR FOR
   SELECT table_name
   FROM information_schema.tables
   WHERE table_type = 'base table'
   
   OPEN TableCursor
   FETCH NEXT FROM TableCursor INTO @TableName
   WHILE @@FETCH_STATUS = 0
   BEGIN
       SET @cmd = 'ALTER INDEX ALL ON [' + @TableName + '] REBUILD WITH (FILLFACTOR = ' + CAST(@fillfactor AS NVARCHAR(3)) + ')'
       EXEC (@cmd)
       FETCH NEXT FROM TableCursor INTO @TableName
   END
   CLOSE TableCursor
   DEALLOCATE TableCursor
   ```

3. **Data Archiving Policy**:
   - Archive invoices older than 5 years
   - Archive error logs older than 6 months
   - Maintain certificate history indefinitely

### System Updates

1. **Application Updates**:
   - Follow standard deployment procedures
   - Schedule updates during off-peak hours
   - Perform database backups before updates
   - Test updates in staging environment first

2. **Dependency Updates**:
   - Regularly update .NET Core runtime
   - Keep database drivers updated
   - Update cryptographic libraries promptly

3. **Security Patches**:
   - Apply OS security patches monthly
   - Apply critical security patches immediately
   - Test patches in staging environment when possible

---

## 9. Troubleshooting

### Common Issues and Solutions

#### Database Connection Issues

**Symptoms**:
- API returns 500 errors
- Logs show database connection failures
- Application startup fails

**Solutions**:
1. Verify connection string in `appsettings.json`
2. Check if SQL Server is running
3. Verify network connectivity to database server
4. Check SQL Server login credentials
5. Ensure database exists and is accessible

#### Certificate Issues

**Symptoms**:
- Device registration fails
- Invoice signing fails
- CSR generation errors

**Solutions**:
1. Verify certificate store path exists and is accessible
2. Check file permissions on certificate store
3. Verify certificate passwords are correct
4. Ensure OpenSSL is installed (Linux environments)
5. Check if certificates have expired

#### ZATCA API Connectivity Issues

**Symptoms**:
- Invoice reporting fails
- Certificate requests fail
- Timeout errors when communicating with ZATCA

**Solutions**:
1. Verify ZATCA API endpoints in configuration
2. Check network connectivity to ZATCA servers
3. Verify firewall allows outbound connections to ZATCA
4. Ensure ZATCA services are operational
5. Check if authentication credentials are valid

#### Authentication Issues

**Symptoms**:
- Unable to obtain JWT token
- API returns 401 Unauthorized errors
- Token validation fails

**Solutions**:
1. Verify JWT configuration in `appsettings.json`
2. Check if user credentials are correct
3. Ensure token has not expired
4. Verify token is properly formatted
5. Check if user has necessary permissions

### Diagnostic Tools

1. **Log Analysis**:
   - Check application logs for errors
   - Use filtering to isolate specific errors
   - Look for patterns in error messages

2. **Database Diagnostics**:
   - Use SQL Server Management Studio for database queries
   - Check SQL Server logs for errors
   - Run database health checks

3. **Network Diagnostics**:
   - Use tools like `ping`, `tracert`, `curl` to test connectivity
   - Check DNS resolution for ZATCA endpoints
   - Verify SSL/TLS handshake with ZATCA servers

### Generating Diagnostic Reports

To generate a system diagnostic report:

```bash
# Generate diagnostic report with curl
curl -H "Authorization: Bearer {admin_token}" https://your-domain.com/api/admin/diagnostics/report
```

This will return a JSON report with system status, including:
- Database connectivity
- ZATCA API connectivity
- Certificate status
- System performance metrics
- Recent errors

---

## 10. Backup & Recovery

### Backup Strategy

Implement the following backup strategy:

1. **Database Backups**:
   - **Full Backup**: Daily at off-peak hours
   - **Differential Backup**: Every 6 hours
   - **Transaction Log Backup**: Every hour

2. **Certificate Store Backup**:
   - Daily backup of certificate store
   - Secure backup with encryption
   - Store backups in a different location

3. **Application Configuration Backup**:
   - Backup `appsettings.json` and other configuration files
   - Include in version control system
   - Document configuration changes

### Backup Procedures

#### SQL Server Backup

```sql
-- Full database backup
BACKUP DATABASE ZatcaPhase2
TO DISK = 'D:\Backups\ZatcaPhase2_Full_' + FORMAT(GETDATE(), 'yyyyMMdd_HHmmss') + '.bak'
WITH COMPRESSION, INIT, NAME = 'ZatcaPhase2-Full Backup',
DESCRIPTION = 'Full backup of ZatcaPhase2 database';

-- Differential backup
BACKUP DATABASE ZatcaPhase2
TO DISK = 'D:\Backups\ZatcaPhase2_Diff_' + FORMAT(GETDATE(), 'yyyyMMdd_HHmmss') + '.bak'
WITH DIFFERENTIAL, COMPRESSION, INIT, NAME = 'ZatcaPhase2-Differential Backup',
DESCRIPTION = 'Differential backup of ZatcaPhase2 database';

-- Transaction log backup
BACKUP LOG ZatcaPhase2
TO DISK = 'D:\Backups\ZatcaPhase2_Log_' + FORMAT(GETDATE(), 'yyyyMMdd_HHmmss') + '.trn'
WITH COMPRESSION, INIT, NAME = 'ZatcaPhase2-Log Backup',
DESCRIPTION = 'Transaction log backup of ZatcaPhase2 database';
```

#### Certificate Store Backup

**Windows**:
```powershell
# Create backup directory
$backupDir = "D:\Backups\Certificates"
$date = Get-Date -Format "yyyyMMdd_HHmmss"
$backupPath = Join-Path $backupDir "CertBackup_$date"
New-Item -ItemType Directory -Path $backupPath -Force

# Copy certificate files
Copy-Item "C:\zatca-api\Certificates\*" -Destination $backupPath -Recurse

# Compress backup
Compress-Archive -Path $backupPath -DestinationPath "$backupPath.zip"
Remove-Item -Path $backupPath -Recurse

# Encrypt backup (optional)
# Use Windows EFS or third-party encryption tool
```

**Linux**:
```bash
# Create backup directory
BACKUP_DIR="/backup/certificates"
DATE=$(date +"%Y%m%d_%H%M%S")
BACKUP_PATH="$BACKUP_DIR/cert_backup_$DATE"
mkdir -p $BACKUP_PATH

# Copy certificate files
cp -R /var/www/zatca-api/Certificates/* $BACKUP_PATH/

# Compress and encrypt backup
tar -czf $BACKUP_PATH.tar.gz $BACKUP_PATH
gpg --symmetric --cipher-algo AES256 $BACKUP_PATH.tar.gz
rm -rf $BACKUP_PATH $BACKUP_PATH.tar.gz
```

#### Configuration Backup

**Windows**:
```powershell
# Backup configuration files
$backupDir = "D:\Backups\Config"
$date = Get-Date -Format "yyyyMMdd_HHmmss"
$backupPath = Join-Path $backupDir "ConfigBackup_$date"
New-Item -ItemType Directory -Path $backupPath -Force

# Copy configuration files
Copy-Item "C:\zatca-api\appsettings*.json" -Destination $backupPath

# Compress backup
Compress-Archive -Path $backupPath -DestinationPath "$backupPath.zip"
Remove-Item -Path $backupPath -Recurse
```

**Linux**:
```bash
# Backup configuration files
BACKUP_DIR="/backup/config"
DATE=$(date +"%Y%m%d_%H%M%S")
BACKUP_PATH="$BACKUP_DIR/config_backup_$DATE"
mkdir -p $BACKUP_PATH

# Copy configuration files
cp /var/www/zatca-api/appsettings*.json $BACKUP_PATH/

# Compress backup
tar -czf $BACKUP_PATH.tar.gz $BACKUP_PATH
rm -rf $BACKUP_PATH
```

### Scheduling Backups

#### Windows Task Scheduler

1. Open Task Scheduler
2. Create a new task
3. Set triggers (daily for full backups, every 6 hours for differential)
4. Add action to run backup script

#### Linux Cron Jobs

```bash
# Edit crontab
crontab -e

# Add the following entries
# Daily full backup at 1 AM
0 1 * * * /path/to/backup/script/full_backup.sh

# Differential backup every 6 hours
0 */6 * * * /path/to/backup/script/diff_backup.sh

# Transaction log backup every hour
0 * * * * /path/to/backup/script/log_backup.sh
```

### Backup Verification

Regularly verify backups to ensure they can be used for recovery:

1. Restore database to a test server
2. Verify application functions correctly with restored database
3. Check certificate integrity
4. Document verification results

### Recovery Procedures

#### Database Recovery

```sql
-- Restore full backup
RESTORE DATABASE ZatcaPhase2
FROM DISK = 'D:\Backups\ZatcaPhase2_Full_20230101_010000.bak'
WITH NORECOVERY;

-- Restore differential backup
RESTORE DATABASE ZatcaPhase2
FROM DISK = 'D:\Backups\ZatcaPhase2_Diff_20230101_060000.bak'
WITH NORECOVERY;

-- Restore transaction log backups
RESTORE LOG ZatcaPhase2
FROM DISK = 'D:\Backups\ZatcaPhase2_Log_20230101_070000.trn'
WITH NORECOVERY;

-- Continue with additional log backups as needed

-- Recover the database
RESTORE DATABASE ZatcaPhase2 WITH RECOVERY;
```

#### Certificate Recovery

**Windows**:
```powershell
# Extract backup
Expand-Archive -Path "D:\Backups\Certificates\CertBackup_20230101_010000.zip" -DestinationPath "D:\Temp\CertRestore"

# Copy certificates to application directory
Copy-Item "D:\Temp\CertRestore\*" -Destination "C:\zatca-api\Certificates\" -Recurse

# Clean up
Remove-Item -Path "D:\Temp\CertRestore" -Recurse
```

**Linux**:
```bash
# Decrypt and extract backup
gpg --decrypt /backup/certificates/cert_backup_20230101_010000.tar.gz.gpg > /tmp/cert_restore.tar.gz
tar -xzf /tmp/cert_restore.tar.gz -C /tmp/

# Copy certificates to application directory
cp -R /tmp/cert_backup_20230101_010000/* /var/www/zatca-api/Certificates/

# Clean up
rm -rf /tmp/cert_restore.tar.gz /tmp/cert_backup_20230101_010000
```

#### Configuration Recovery

**Windows**:
```powershell
# Extract backup
Expand-Archive -Path "D:\Backups\Config\ConfigBackup_20230101_010000.zip" -DestinationPath "D:\Temp\ConfigRestore"

# Copy configuration files to application directory
Copy-Item "D:\Temp\ConfigRestore\appsettings*.json" -Destination "C:\zatca-api\"

# Clean up
Remove-Item -Path "D:\Temp\ConfigRestore" -Recurse
```

**Linux**:
```bash
# Extract backup
tar -xzf /backup/config/config_backup_20230101_010000.tar.gz -C /tmp/

# Copy configuration files to application directory
cp /tmp/config_backup_20230101_010000/appsettings*.json /var/www/zatca-api/

# Clean up
rm -rf /tmp/config_backup_20230101_010000
```

### Disaster Recovery Plan

1. **Preparation**:
   - Maintain off-site backups
   - Document recovery procedures
   - Train staff on recovery processes
   - Test recovery procedures regularly

2. **Recovery Steps**:
   - Provision new server infrastructure if needed
   - Restore database from latest backups
   - Restore certificate store
   - Restore configuration files
   - Verify system functionality
   - Update DNS/load balancers to point to new infrastructure

3. **Post-Recovery**:
   - Verify all components are functioning
   - Check connectivity to ZATCA
   - Test invoice submission
   - Document the incident and recovery process
   - Review and improve disaster recovery plan

---

## 11. Security Best Practices

### Network Security

1. **Firewall Configuration**:
   - Allow only necessary inbound/outbound traffic
   - Restrict access to API endpoints by IP
   - Implement web application firewall (WAF)

2. **TLS Configuration**:
   - Use TLS 1.2 or higher
   - Implement strong cipher suites
   - Regularly update SSL certificates

3. **Network Segmentation**:
   - Place API servers in a separate network segment
   - Isolate database servers
   - Use VPN for administrative access

### Application Security

1. **JWT Security**:
   - Use strong keys for token signing
   - Set appropriate token expiry times
   - Implement token revocation for suspicious activity

2. **Input Validation**:
   - Validate all input parameters
   - Sanitize data to prevent injection attacks
   - Implement request size limits

3. **API Rate Limiting**:
   - Implement rate limiting to prevent abuse
   - Set different limits for different endpoints
   - Log and alert on rate limit violations

### Certificate Security

1. **Private Key Protection**:
   - Store private keys securely
   - Encrypt private keys at rest
   - Restrict access to private keys

2. **Certificate Rotation**:
   - Renew certificates well before expiry
   - Implement certificate monitoring
   - Plan for certificate revocation scenarios

3. **HSM Integration** (optional but recommended):
   - Use Hardware Security Modules for key storage
   - Implement HSM-based signing operations
   - Ensure HSM is properly configured and secured

### Database Security

1. **Data Encryption**:
   - Implement TDE (Transparent Data Encryption)
   - Encrypt sensitive columns
   - Use secure connection strings

2. **Access Control**:
   - Use least privilege principle
   - Implement row-level security where needed
   - Audit database access

3. **SQL Injection Prevention**:
   - Use parameterized queries
   - Implement ORM security best practices
   - Validate all SQL inputs

### Security Monitoring

1. **Audit Logging**:
   - Log all authentication attempts
   - Log administrative actions
   - Log certificate operations

2. **Intrusion Detection**:
   - Monitor for suspicious activities
   - Set up alerts for potential security breaches
   - Regularly review security logs

3. **Vulnerability Management**:
   - Conduct regular security assessments
   - Apply security patches promptly
   - Perform penetration testing

### Physical Security

1. **Server Room Security**:
   - Restrict physical access to servers
   - Implement environmental controls
   - Monitor physical access

2. **Backup Media Security**:
   - Secure backup storage
   - Encrypt backup media
   - Implement secure transportation procedures

### Compliance Requirements

1. **ZATCA Compliance**:
   - Follow ZATCA security requirements
   - Maintain required audit trails
   - Implement proper invoice signing

2. **Data Protection**:
   - Comply with Saudi data protection regulations
   - Implement data retention policies
   - Secure personal and business data

3. **Audit Readiness**:
   - Maintain documentation for compliance audits
   - Be prepared for ZATCA audits
   - Implement audit trail for all e-invoicing operations

---

## 12. Appendices

### Appendix A: Database Schema

```sql
-- Database Schema Script
CREATE TABLE Users (
    Id INT IDENTITY(1,1) PRIMARY KEY,
    Username NVARCHAR(50) NOT NULL UNIQUE,
    PasswordHash NVARCHAR(100) NOT NULL,
    Email NVARCHAR(100),
    CompanyName NVARCHAR(100),
    VatRegistrationNumber NVARCHAR(15),
    Role INT NOT NULL
);

CREATE TABLE Devices (
    Id INT IDENTITY(1,1) PRIMARY KEY,
    DeviceSerialNumber NVARCHAR(50) NOT NULL UNIQUE,
    DeviceName NVARCHAR(100) NOT NULL,
    Model NVARCHAR(50) NOT NULL,
    HardwareVersion NVARCHAR(20),
    SoftwareVersion NVARCHAR(20),
    ZatcaDeviceId NVARCHAR(50),
    ZatcaDeviceToken NVARCHAR(100),
    RegistrationDate DATETIME2,
    LastCommunicationDate DATETIME2,
    Status INT NOT NULL,
    VatRegistrationNumber NVARCHAR(15),
    CompanyName NVARCHAR(100),
    CommercialRegistrationNumber NVARCHAR(20),
    StreetName NVARCHAR(100),
    BuildingNumber NVARCHAR(20),
    CityName NVARCHAR(50),
    DistrictName NVARCHAR(50),
    PostalCode NVARCHAR(10),
    CountryCode NVARCHAR(2),
    CertificateContent NVARCHAR(MAX),
    PrivateKeyContent NVARCHAR(MAX),
    CsrContent NVARCHAR(MAX),
    CertificateSerialNumber NVARCHAR(50),
    OTP NVARCHAR(10),
    CertificateExpiryDate DATETIME2,
    CertificateType INT DEFAULT 0,
    IsCertificateRenewRequired BIT DEFAULT 0
);

CREATE TABLE InvoiceReports (
    Id INT IDENTITY(1,1) PRIMARY KEY,
    DocumentNumber NVARCHAR(50) NOT NULL,
    DocumentDate DATETIME2 NOT NULL,
    DocumentIssueTime DATETIME2 NOT NULL,
    SellerName NVARCHAR(100) NOT NULL,
    SellerVatNumber NVARCHAR(15) NOT NULL,
    SellerStreetName NVARCHAR(100),
    SellerBuildingNumber NVARCHAR(20),
    SellerCityName NVARCHAR(50),
    SellerPostalCode NVARCHAR(10),
    SellerDistrictName NVARCHAR(50),
    SellerCountryCode NVARCHAR(2),
    BuyerName NVARCHAR(100) NOT NULL,
    BuyerVatNumber NVARCHAR(15) NOT NULL,
    BuyerStreetName NVARCHAR(100),
    BuyerBuildingNumber NVARCHAR(20),
    BuyerCityName NVARCHAR(50),
    BuyerPostalCode NVARCHAR(10),
    BuyerDistrictName NVARCHAR(50),
    BuyerCountryCode NVARCHAR(2),
    TotalAmount DECIMAL(18,2) NOT NULL,
    VatAmount DECIMAL(18,2) NOT NULL,
    TotalWithVat DECIMAL(18,2),
    TotalWithoutVat DECIMAL(18,2),
    Discount DECIMAL(18,2),
    DocumentUUID NVARCHAR(36),
    PIH NVARCHAR(MAX),
    DocumentHash NVARCHAR(MAX),
    DocumentXml NVARCHAR(MAX),
    SignedDocumentXml NVARCHAR(MAX),
    EmbeddedQRCode NVARCHAR(MAX),
    ZatcaResponse NVARCHAR(MAX),
    ZatcaReportingStatus NVARCHAR(50),
    ZatcaValidationResults NVARCHAR(MAX),
    ZatcaComplianceStatus NVARCHAR(50),
    ZatcaQrCode NVARCHAR(MAX),
    ZatcaReportId NVARCHAR(50),
    ReportingDate DATETIME2,
    ClearanceDate DATETIME2,
    ClearanceStatus INT DEFAULT 0,
    CreatedAt DATETIME2 NOT NULL DEFAULT GETDATE(),
    DeviceSerialNumber NVARCHAR(50),
    InvoiceType INT NOT NULL,
    TransactionType INT NOT NULL DEFAULT 0,
    InvoiceCurrency NVARCHAR(3) DEFAULT 'SAR',
    PaymentMethod NVARCHAR(20),
    PaymentDueDate DATETIME2
);

CREATE TABLE InvoiceLineItems (
    Id INT IDENTITY(1,1) PRIMARY KEY,
    InvoiceReportId INT NOT NULL,
    LineNumber INT NOT NULL,
    ItemName NVARCHAR(100) NOT NULL,
    ItemDescription NVARCHAR(200),
    Quantity DECIMAL(18,2) NOT NULL,
    UnitOfMeasure NVARCHAR(10) NOT NULL,
    UnitPrice DECIMAL(18,2) NOT NULL,
    NetAmount DECIMAL(18,2) NOT NULL,
    VatRate DECIMAL(5,2) NOT NULL,
    VatAmount DECIMAL(18,2) NOT NULL,
    TotalAmount DECIMAL(18,2) NOT NULL,
    DiscountAmount DECIMAL(18,2),
    DiscountPercentage DECIMAL(5,2),
    CONSTRAINT FK_InvoiceLineItems_InvoiceReports FOREIGN KEY (InvoiceReportId) REFERENCES InvoiceReports(Id)
);

-- Add similar tables for CreditNoteReports, DebitNoteReports, SalesReturnReports
```

### Appendix B: Common Error Codes

| Error Code | Description | Troubleshooting Steps |
|------------|-------------|------------------------|
| DB001 | Database connection failure | Check connection string, verify SQL Server is running |
| DB002 | Database query timeout | Optimize query, check index fragmentation |
| AUTH001 | Authentication failed | Verify credentials, check if account is locked |
| AUTH002 | Token validation failed | Check token expiry, verify token is properly formatted |
| CERT001 | Certificate generation failed | Check OpenSSL installation, verify permissions |
| CERT002 | Certificate expired | Renew certificate, check system time |
| API001 | ZATCA API connection failure | Check network connectivity, verify endpoint URLs |
| API002 | ZATCA API authentication failure | Verify credentials, check certificate validity |
| INV001 | Invoice validation failed | Check XML format, verify required fields |
| INV002 | Invoice signing failed | Check certificate, verify private key access |
| QR001 | QR code generation failed | Check TLV implementation, verify input data |

### Appendix C: Performance Tuning

#### Database Performance

1. **Index Optimization**:
   ```sql
   -- Add indexes for frequently queried fields
   CREATE INDEX IX_Devices_Status ON Devices(Status);
   CREATE INDEX IX_InvoiceReports_DocumentNumber ON InvoiceReports(DocumentNumber);
   CREATE INDEX IX_InvoiceReports_ZatcaReportId ON InvoiceReports(ZatcaReportId);
   CREATE INDEX IX_InvoiceReports_DeviceSerialNumber ON InvoiceReports(DeviceSerialNumber);
   CREATE INDEX IX_InvoiceReports_DocumentDate ON InvoiceReports(DocumentDate);
   CREATE INDEX IX_InvoiceReports_ClearanceStatus ON InvoiceReports(ClearanceStatus);
   ```

2. **Query Optimization**:
   - Use parameterized queries
   - Avoid SELECT *
   - Use appropriate JOINs
   - Implement paging for large result sets

3. **Database Configuration**:
   - Allocate sufficient memory to SQL Server
   - Configure tempdb appropriately
   - Set proper MAXDOP settings

#### Application Performance

1. **Connection Pooling**:
   - Use connection pooling for database connections
   - Implement proper connection string parameters

2. **Caching**:
   - Implement in-memory caching for frequently accessed data
   - Cache device information
   - Cache validation results

3. **Asynchronous Operations**:
   - Use async/await pattern for I/O operations
   - Implement background processing for long-running tasks
   - Use task-based programming model

#### API Performance

1. **Response Compression**:
   - Enable HTTP compression
   - Compress large responses

2. **Batch Processing**:
   - Implement batch endpoints for multiple operations
   - Use bulk database operations

3. **Rate Limiting**:
   - Implement appropriate rate limits
   - Set different limits for different operations
   - Use token bucket algorithm for rate limiting

### Appendix D: Glossary

| Term | Definition |
|------|------------|
| ZATCA | Zakat, Tax and Customs Authority of Saudi Arabia |
| CSR | Certificate Signing Request |
| JWT | JSON Web Token, used for authentication |
| TLV | Tag-Length-Value, format used for QR codes |
| UBL | Universal Business Language, XML standard for business documents |
| HSM | Hardware Security Module |
| TDE | Transparent Data Encryption |
| OTP | One-Time Password, used for certificate requests |

### Appendix E: Reference Documents

1. [ZATCA E-Invoicing Technical Specifications](https://zatca.gov.sa/en/E-Invoicing/Introduction/Pages/Technical-Specifications.aspx)
2. [ZATCA Developer Portal](https://developer.zatca.gov.sa/)
3. [UBL 2.1 Standard](http://docs.oasis-open.org/ubl/UBL-2.1.html)
4. [.NET Core Documentation](https://docs.microsoft.com/en-us/aspnet/core/)
5. [SQL Server Management Documentation](https://docs.microsoft.com/en-us/sql/sql-server/)
6. [PKCS Standards for Cryptography](https://tools.ietf.org/html/rfc7292)

### Appendix F: Change Log Template

| Date | Version | Description | Author |
|------|---------|-------------|--------|
| 2023-01-01 | 1.0.0 | Initial release | Admin |
| 2023-02-15 | 1.0.1 | Updated ZATCA endpoints | Admin |
| 2023-03-20 | 1.1.0 | Added support for batch processing | Admin |
| 2023-04-10 | 1.1.1 | Security enhancements | Admin |

### Appendix G: Contact Information

| Role | Name | Email | Phone |
|------|------|-------|-------|
| System Administrator | [Name] | admin@example.com | +966-XX-XXXXXXX |
| Database Administrator | [Name] | dba@example.com | +966-XX-XXXXXXX |
| Security Officer | [Name] | security@example.com | +966-XX-XXXXXXX |
| ZATCA Support | ZATCA Support | support@zatca.gov.sa | [ZATCA Support Number] |

### Appendix H: Maintenance Schedule Template

| Maintenance Task | Frequency | Duration | Responsible |
|------------------|-----------|----------|-------------|
| Database Backup | Daily | 1 hour | DBA |
| Index Maintenance | Weekly | 2 hours | DBA |
| Certificate Monitoring | Weekly | 1 hour | Security Officer |
| System Updates | Monthly | 4 hours | System Administrator |
| Security Patching | As needed | Varies | System Administrator |
| Performance Review | Monthly | 2 hours | DBA |
