# AWS EC2 Instance Controller

Multi-region AWS EC2 instance management tool (Windows GUI)

![Language](https://img.shields.io/badge/Go-00ADD8?logo=go&logoColor=white)
![Platform](https://img.shields.io/badge/Windows-0078D6?logo=windows&logoColor=white)

## Features

- **Multi-region**: Manage EC2 instances across all AWS regions
- **Batch operations**: Start/Stop/Terminate multiple instances
- **Protection**: Toggle termination/stop protection with one click
- **Security**: AES-256-GCM encrypted credential storage
- **Auto-refresh**: Updates instance states during transitions

## Quick Start

1. Download `aws_control.exe` from [Releases](../../releases)
2. Run the executable
3. Enter AWS credentials and click Login
4. Select instances and use control buttons

## Required AWS Permissions
```json
{
  "Effect": "Allow",
  "Action": [
    "ec2:DescribeInstances",
    "ec2:DescribeRegions",
    "ec2:DescribeInstanceAttribute",
    "ec2:StartInstances",
    "ec2:StopInstances",
    "ec2:TerminateInstances",
    "ec2:ModifyInstanceAttribute"
  ],
  "Resource": "*"
}
```

## Build from Source
```bash
# Prerequisites: Go 1.21+

# Clone
git clone https://github.com/littl3-kitty/Aws_EC2_Controller.git
cd Aws_EC2_Controller

# Build
make build-windows

# Output: dist/aws_control.exe
```

## Tech Stack

- **Go 1.21+**: Core language
- **Fyne v2**: GUI framework
- **AWS SDK v2**: EC2 management

## Why Go (vs Python)?

| Aspect | Python | Go |
|--------|--------|-----|
| Cross-compile | ❌ | ✅ Native |
| Binary size | 50MB+ | 36MB |
| Startup | 2-3s | Instant |
| Jenkins | Windows VM needed | Linux only |

## Security

- Credentials encrypted with AES-256-GCM
- Encryption key derived from hardware ID
- Stored in `~/.aws_ctrl/credentials.enc`

## License

MIT-Based (Non-Commercial) - See [LICENSE](LICENSE)

## Disclaimer

⚠️ This tool can **permanently delete** EC2 instances. Use carefully!
