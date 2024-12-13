# AWS Security Scanner Documentation

## Table of Contents
1. [Overview](#overview)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [Usage](#usage)
5. [API Reference](#api-reference)
6. [Troubleshooting](#troubleshooting)

## Overview

AWS Security Scanner is a comprehensive security assessment tool for AWS environments. It performs automated security checks across multiple AWS services, identifies potential security risks, and provides detailed reports and alerts.

### Features
- Multi-service security scanning
- Real-time alerting
- Compliance checking
- Customizable rules
- Multiple notification channels
- REST API interface
- Detailed reporting

## Installation

### Prerequisites
- Docker and Docker Compose
- AWS credentials with appropriate permissions
- Python 3.8+ (for local development)

### Docker Installation

1. Clone the repository:
git clone https://github.com/yourusername/aws-security-scanner.git
cd aws-security-scanner

2. Create configuration file:
cp config/config.example.yaml config/config.yaml

3. Configure AWS credentials:
mkdir -p ~/.aws
touch ~/.aws/credentials
touch ~/.aws/config

4. Start the services:
docker-compose up -d

### Local Installation

1. Create virtual environment:
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

2. Install dependencies:
pip install -r requirements.txt

## Configuration

### Basic Configuration
Edit `config/config.yaml` to configure the scanner:

aws:
  regions:
    - us-east-1
  role_arn: "arn:aws:iam::123456789012:role/SecurityScannerRole"
  external_id: "your-external-id"

scanners:
  enabled_scanners:
    - iam
    - s3
    - ec2

### Environment Variables
- `AWS_PROFILE`: AWS credentials profile
- `AWS_DEFAULT_REGION`: Default AWS region
- `LOG_LEVEL`: Logging level
- `SCANNER_CONFIG`: Path to config file

### AWS Permissions
Required IAM permissions:
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:GetAccountPasswordPolicy",
                "s3:ListAllMyBuckets",
                "ec2:DescribeInstances"
                // Add other required permissions
            ],
            "Resource": "*"
        }
    ]
}

## Usage

### Command Line Interface

1. Run a scan:
docker-compose exec scanner aws-security-scanner scan

2. Generate report:
docker-compose exec scanner aws-security-scanner report

3. Check specific service:
docker-compose exec scanner aws-security-scanner scan --service s3

### REST API

The scanner provides a REST API on port 8080.

1. Start a scan:
curl -X POST http://localhost:8080/api/v1/scans

2. Get scan status:
curl http://localhost:8080/api/v1/scans/{scan_id}

3. Get findings:
curl http://localhost:8080/api/v1/findings

## API Reference

### Endpoints

#### Scans
- `POST /api/v1/scans`: Start new scan
- `GET /api/v1/scans`: List all scans
- `GET /api/v1/scans/{scan_id}`: Get scan details
- `DELETE /api/v1/scans/{scan_id}`: Cancel scan

#### Findings
- `GET /api/v1/findings`: List all findings
- `GET /api/v1/findings/{finding_id}`: Get finding details
- `PUT /api/v1/findings/{finding_id}/status`: Update finding status

#### Reports
- `POST /api/v1/reports`: Generate new report
- `GET /api/v1/reports`: List all reports
- `GET /api/v1/reports/{report_id}`: Download report

## Troubleshooting

### Common Issues

1. AWS Authentication Failed
Error: Unable to locate credentials
Solution: Ensure AWS credentials are properly configured in ~/.aws/credentials

2. Permission Denied
Error: User is not authorized to perform action
Solution: Verify IAM permissions and role configuration

3. Scanner Not Starting
Error: Unable to start scanner service
Solution: Check Docker logs and ensure all dependencies are running

### Logging

Access logs:
docker-compose logs scanner

Enable debug logging:
logging:
  level: DEBUG

### Health Checks

Check service health:
docker-compose exec scanner aws-security-scanner health

### Support

For additional support:
1. Check GitHub Issues
2. Review documentation
3. Contact security team

## Development

### Contributing
1. Fork repository
2. Create feature branch
3. Submit pull request

### Testing
# Run tests
docker-compose exec scanner pytest

# Run linting
docker-compose exec scanner flake8

### Building Documentation
```bash
# Generate API documentation
docker-compose exec scanner make docs
