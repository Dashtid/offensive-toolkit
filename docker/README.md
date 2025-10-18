# Docker Configuration

Docker and container orchestration files for the Offensive Security Toolkit.

## Files

- **Dockerfile** - Multi-stage Docker build configuration
- **docker-compose.yml** - Container orchestration setup

## Quick Start

### Build and Run with Docker Compose
```bash
cd /path/to/offensive-toolkit
docker-compose -f docker/docker-compose.yml up -d
```

### Build Docker Image
```bash
docker build -f docker/Dockerfile -t offensive-toolkit:latest .
```

### Run Container
```bash
docker run -it --rm \
  -v $(pwd)/output:/app/output \
  -v $(pwd)/config:/app/config \
  offensive-toolkit:latest
```

## Environment Variables

Configure the toolkit using environment variables in docker-compose.yml or pass them at runtime:

- `CONFIG_PATH` - Path to configuration file
- `OUTPUT_DIR` - Output directory for results
- `LOG_LEVEL` - Logging level (DEBUG, INFO, WARNING, ERROR)

## Security Notes

[!] This toolkit is designed for authorized security testing only.
- Never run against unauthorized targets
- Ensure you have written authorization before scanning
- Review and understand all configurations before deployment
