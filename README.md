# Checkmarx ONE Compliance Pipeline

A comprehensive Jenkins pipeline for automated security scanning using Checkmarx ONE CLI. This pipeline automates the process of cloning repositories, running security scans, and generating detailed reports with configurable thresholds.

## 🚀 Features

- **Automated Repository Cloning**: Supports both public and private GitHub repositories
- **Checkmarx ONE CLI Integration**: Automatic CLI download and management
- **Configurable Security Thresholds**: Set failure thresholds for different scan engines and severity levels
- **Multiple Report Formats**: Support for PDF, HTML, JSON, SARIF, Sonar, and Markdown formats
- **PDF Report Customization**: Configurable report sections and email delivery
- **Robust Error Handling**: Comprehensive error handling and debugging output
- **Jenkins Parameterization**: Fully configurable via Jenkins UI parameters

## 📋 Prerequisites

- **Jenkins Server**: Jenkins 2.0+ with Pipeline plugin
- **GitHub Access**: Personal Access Token for repository access
- **Checkmarx ONE Account**: Valid API key for authentication
- **Linux Environment**: Pipeline is designed for Linux Jenkins agents

## 🔧 Installation

1. **Clone this repository**:
   ```bash
   git clone https://github.com/yourusername/checkmarx-compliance-pipeline.git
   cd checkmarx-compliance-pipeline
   ```

2. **Create a new Jenkins Pipeline**:
   - Go to Jenkins → New Item → Pipeline
   - Name: `Checkmarx Compliance Pipeline`
   - Copy the contents of `clientreportjira.groovy` into the Pipeline script section

3. **Configure Required Credentials**:
   - **GitHub Personal Access Token**: For repository access
   - **Checkmarx ONE API Key**: For authentication

## ⚙️ Configuration

### Required Parameters

| Parameter | Description | Required |
|-----------|-------------|----------|
| `GITHUB_API_KEY` | GitHub Personal Access Token | Yes |
| `CX_API_KEY` | Checkmarx ONE API Key | Yes |
| `REPO_OWNER` | Repository owner/organization | Yes |
| `REPO_NAME` | Repository name | Yes |

### Optional Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `BRANCH_OR_TAG` | Branch or tag to scan | `master` |
| `SOURCE_PATH` | Source path to scan | `.` |
| `EMAIL_RECIPIENT` | Email for PDF reports | `admin@company.com` |
| `CLI_VERSION` | Checkmarx CLI version | `2.3.30` |
| `CX_REPORT_FORMAT` | Report format | `pdf` |
| `CX_SCAN_TIMEOUT` | Scan timeout (seconds) | `3600` |
| `CX_THRESHOLDS` | Security thresholds | (none) |
| `CX_PDF_SECTIONS` | PDF report sections | `all` |

### Threshold Configuration

Set security thresholds to automatically fail the pipeline when security standards are not met:

```bash
# Example thresholds
"sast-high=10; sast-medium=20; sca-high=10; containers-high=5"
```

**Threshold Syntax**:
- `engine-severity=count`
- Multiple thresholds separated by semicolons
- OR logic: pipeline fails if ANY threshold is exceeded

**Supported Engines**:
- `sast` - Static Application Security Testing
- `sca` - Software Composition Analysis
- `containers` - Container scanning
- `iac` - Infrastructure as Code

**Severity Levels**:
- `high` - High severity vulnerabilities
- `medium` - Medium severity vulnerabilities
- `low` - Low severity vulnerabilities

## 🔍 Usage

### Basic Scan

1. **Run the Pipeline** with required parameters:
   - `GITHUB_API_KEY`: Your GitHub token
   - `CX_API_KEY`: Your Checkmarx ONE API key
   - `REPO_OWNER`: Repository owner
   - `REPO_NAME`: Repository name

2. **Monitor Progress**:
   - **Prepare Stage**: CLI download and verification
   - **Clone Stage**: Repository cloning
   - **Scan Stage**: Security scanning and reporting

### Advanced Configuration

#### Custom Thresholds
```bash
CX_THRESHOLDS="sast-high=5; sca-high=15; containers-high=3"
```

#### PDF Report Customization
```bash
CX_REPORT_FORMAT=pdf
CX_PDF_SECTIONS="summary,details,remediation"
EMAIL_RECIPIENT="security@company.com"
```

#### Multiple Report Formats
```bash
CX_REPORT_FORMAT="json,sarif,pdf"
```

## 📊 Output

### Scan Results
- **Console Output**: Real-time scan progress and results
- **Reports**: Generated in specified formats
- **Threshold Validation**: Automatic failure if thresholds exceeded

### Report Types

#### Scan Summary Report
- Available in: HTML, JSON, Console, Markdown
- Content: Risk counts by type and severity

#### Complete Scan Report
- Available in: JSON, SARIF, Sonar
- Content: Detailed information about each identified risk

#### PDF Reports
- Customizable sections
- Email delivery with download links
- Professional formatting

## 🛠️ Troubleshooting

### Common Issues

1. **Repository Cloning Fails**:
   - Verify GitHub API key has repository access
   - Check repository name and owner spelling
   - Ensure repository exists and is accessible

2. **CLI Download Issues**:
   - Check internet connectivity
   - Verify CLI version parameter
   - Check Jenkins agent permissions

3. **Scan Failures**:
   - Verify Checkmarx ONE API key
   - Check scan timeout settings
   - Review threshold configurations

### Debug Mode

Enable debug mode for verbose output:
```bash
DEBUG=true
```

## 🔒 Security

- **API Keys**: Never commit API keys to version control
- **Credentials**: Use Jenkins credentials store for sensitive data
- **Access Control**: Restrict pipeline access to authorized users
- **Audit Logging**: All scan activities are logged

## 📈 Best Practices

1. **Threshold Management**:
   - Start with conservative thresholds
   - Gradually tighten based on security maturity
   - Monitor threshold effectiveness

2. **Report Management**:
   - Use appropriate report formats for different stakeholders
   - Implement automated report distribution
   - Archive reports for compliance

3. **Pipeline Maintenance**:
   - Regular CLI version updates
   - Monitor scan performance
   - Review and update thresholds

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/checkmarx-compliance-pipeline/issues)
- **Documentation**: [Checkmarx ONE Documentation](https://checkmarx.com/resource-library/)
- **Community**: [Checkmarx Community](https://community.checkmarx.com/)

## 🙏 Acknowledgments

- **Checkmarx Team**: For the excellent CLI tool and API
- **Jenkins Community**: For the robust pipeline framework
- **Open Source Contributors**: For inspiration and best practices

---

**Note**: This pipeline is designed for enterprise security scanning. Ensure compliance with your organization's security policies and procedures.
