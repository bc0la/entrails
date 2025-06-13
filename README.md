# entrails

Enumerate actions and principals via readable CloudTrail buckets using a compromised account. Based on the awesome work by https://github.com/carlospolop/Cloudtrail2IAM

```
▓█████  ███▄    █ ▄▄▄█████▓ ██▀███   ▄▄▄       ██▓ ██▓      ██████ 
▓█   ▀  ██ ▀█   █ ▓  ██▒ ▓▒▓██ ▒ ██▒▒████▄    ▓██▒▓██▒    ▒██    ▒ 
▒███   ▓██  ▀█ ██▒▒ ▓██░ ▒░▓██ ░▄█ ▒▒██  ▀█▄  ▒██▒▒██░    ░ ▓██▄   
▒▓█  ▄ ▓██▒  ▐▌██▒░ ▓██▓ ░ ▒██▀▀█▄  ░██▄▄▄▄██ ░██░▒██░      ▒   ██▒
░▒████▒▒██░   ▓██░  ▒██▒ ░ ░██▓ ▒██▒ ▓█   ▓██▒░██░░██████▒▒██████▒▒
░░ ▒░ ░░ ▒░   ▒ ▒   ▒ ░░   ░ ▒▓ ░▒▓░ ▒▒   ▓▒█░░▓  ░ ▒░▓  ░▒ ▒▓▒ ▒ ░
 ░ ░  ░░ ░░   ░ ▒░    ░      ░▒ ░ ▒░  ▒   ▒▒ ░ ▒ ░░ ░ ▒  ░░ ░▒  ░ ░
   ░      ░   ░ ░   ░        ░░   ░   ░   ▒    ▒ ░  ░ ░   ░  ░  ░  
   ░  ░         ░             ░           ░  ░ ░      ░  ░      ░  
```                                                                

## Installation

### Prerequisites

- AWS CLI configured with appropriate credentials
- Access to S3 buckets containing CloudTrail logs

### Build from source

```bash
git clone https://github.com/bc0la/entrails.git
cd entrails
go build -o entrails main.go
```

## Usage

### Basic Usage

```bash
./entrails --bucket "your-cloudtrail-bucket" --prefix "AWSLogs/"
```

### Advanced Usage

```bash
./entrails \
  --bucket "your-cloudtrail-bucket" \
  --prefix "AWSLogs/" \
  --profile "my-profile" \
  --identity "arn:aws:iam::123456789012:user/suspicious-user" \
  --threads 20 \
  --output "analysis-results.txt"
```

### Command Line Options

| Flag | Description | Required | Default |
|------|-------------|----------|---------|
| `--bucket` | S3 bucket name containing CloudTrail logs | Yes | - |
| `--prefix` | S3 prefix for CloudTrail logs (e.g., `AWSLogs/<account-id>/CloudTrail/`) | Yes | - |
| `--profile` | AWS CLI profile to use for authentication | No | default |
| `--identity` | Filter by specific identity ARN | No | caller identity |
| `--threads` | Number of worker threads for processing | No | 10 |
| `--output` | Write results to specified file | No | console only |

## Output

The tool provides two types of output:

### 1. Successful Actions
Lists all successful AWS API calls made by the target identity, including:
- Action name (service:operation format)
- Timestamp of the most recent occurrence

Example:
```
Actions by arn:aws:iam::123456789012:user/example-user:
- ec2:DescribeInstances (2024-01-15T10:30:00Z)
- s3:GetObject (2024-01-15T11:45:00Z)
- iam:ListUsers (2024-01-15T12:00:00Z)
```

### 2. Secrets Manager Access
If the identity accessed AWS Secrets Manager, lists the secret identifiers accessed by ALL principals:
```
Potential Secrets Manager secrets:
- prod/database/credentials
- app/api-keys/external-service
```

More principal discovery coming soon!

### AWS Permissions
The tool requires the following AWS permissions:
- `s3:ListBucket` on the CloudTrail bucket
- `s3:GetObject` on CloudTrail log files
- `sts:GetCallerIdentity` (if not specifying custom identity)



## Opsec

- This tool creates a large amount of authenticated GetObject actions
- Discovered secrets manager secrets are not guarunteed to be readable
- IAM policies can change, so what an identity was able to do a year ago may not still assigned.
