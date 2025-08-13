pipeline {
    /* 
     * ========================================================================
     * CHECKMARX ONE COMPLIANCE PIPELINE
     * ========================================================================
     * 
     * PURPOSE: This pipeline automates security scanning of a single repository
     *          using the Checkmarx ONE CLI. It downloads the CLI, clones the repo,
     *          and runs security scans with comprehensive reporting.
     * 
     * WORKFLOW:
     * 1. Prepare: Download and setup Checkmarx ONE CLI
     * 2. Clone Repository: Clone the specified repository
     * 3. Scan Repository: Run security scan with enhanced parameters including thresholds and PDF reports
     * 
     * PREREQUISITES:
     * - GitHub Personal Access Token (provided via parameter)
     * - Checkmarx ONE API Key (provided via parameter)
     * 
     * SECURITY NOTE: This pipeline requires API keys to be provided via Jenkins parameters
     *               or credentials store. Never commit API keys to version control.
     * 
     * AUTHOR: Sean Carroll
     * LAST UPDATED: 2025
     * ========================================================================
     */
    
    agent any

    parameters {
        /* 
         * PIPELINE PARAMETERS
         * These parameters allow users to customize the pipeline behavior
         * without modifying the code. They appear in the Jenkins UI.
         */
        booleanParam(name: 'DEBUG', defaultValue: false, description: 'Enable verbose debugging output')
        string(
            name: 'REPO_NAME',
            defaultValue: 'pnpm-cx-ghaction',
            description: 'Repository name to scan'
        )
        string(
            name: 'REPO_OWNER',
            defaultValue: 'cx-sean-carroll',
            description: 'Repository owner/organization'
        )
        string(
            name: 'BRANCH_OR_TAG',
            defaultValue: 'master',
            description: 'Branch or tag to scan'
        )
        string(
            name: 'SOURCE_PATH',
            defaultValue: '.',
            description: 'Source path to scan (default: current directory)'
        )
        string(
            name: 'EMAIL_RECIPIENT',
            defaultValue: 'Sean.Carroll@checkmarx.com',
            description: 'Email address to receive scan reports'
        )
        string(
            name: 'CLI_VERSION',
            defaultValue: '2.3.30',
            description: 'Checkmarx ONE CLI version to download (latest: 2.3.30)'
        )
        string(
            name: 'GITHUB_API_KEY',
            defaultValue: '',
            description: 'GitHub Personal Access Token for repository access (required for private repositories)'
        )
        string(
            name: 'CX_API_KEY',
            defaultValue: '',
            description: 'Checkmarx ONE API Key for authentication (required)'
        )
        string(
            name: 'CX_REPORT_FORMAT',
            defaultValue: 'pdf',
            description: 'Report format (pdf, html, json, sarif, sonar, markdown)'
        )
        string(
            name: 'CX_SCAN_TIMEOUT',
            defaultValue: '3600',
            description: 'Scan timeout in seconds (default: 1 hour)'
        )
        string(
            name: 'CX_THRESHOLDS',
            defaultValue: '',
            description: 'Scan thresholds (e.g., "sast-high=10; sast-medium=20; sca-high=10")'
        )
        string(
            name: 'CX_PDF_SECTIONS',
            defaultValue: 'all',
            description: 'PDF report sections to include (e.g., "all" or "summary,details,remediation")'
        )
    }

    environment {
        /* 
         * ENVIRONMENT VARIABLES
         * These define paths and settings used throughout the pipeline
         */
        
        /* Folder where we cache the CLI */
        CLI_DIR = 'CxONE_CLI'
    }

    stages {
        stage('Prepare') {
            steps {
                script {
                    /* Validate required parameters */
                    if (!params.GITHUB_API_KEY?.trim()) {
                        error("GitHub API Key is required. Please provide a valid Personal Access Token.")
                    }
                    if (!params.CX_API_KEY?.trim()) {
                        error("Checkmarx ONE API Key is required. Please provide a valid API key.")
                    }
                    
                    /* Propagate debug flag to env so helper functions can read it */
                    env.DEBUG = params.DEBUG.toString()
                    
                    /* Log parameter values for debugging */
                    echo "Using repository: ${params.REPO_OWNER}/${params.REPO_NAME}"
                    echo "Using branch/tag: ${params.BRANCH_OR_TAG}"
                    echo "Using source path: ${params.SOURCE_PATH}"
                    echo "Using email recipient: ${params.EMAIL_RECIPIENT}"
                    echo "Using CLI version parameter: ${params.CLI_VERSION}"
                    echo "Using report format: ${params.CX_REPORT_FORMAT}"
                    echo "Using scan timeout: ${params.CX_SCAN_TIMEOUT} seconds"

                    /* -------------------------------------------------------------------
                     * CLI DOWNLOAD SECTION
                     * 
                     * PURPOSE: Download and extract the Checkmarx ONE CLI tool
                     * 
                     * LOGIC:
                     * - Check if CLI already exists to avoid re-downloading
                     * - Download from GitHub releases
                     * - Extract the archive and clean up temporary files
                     * - Cache the CLI in workspace for reuse across builds
                     * 
                     * DOWNLOAD URL:
                     * - Linux: https://github.com/Checkmarx/ast-cli/releases/download/{VERSION}/ast-cli_{VERSION}_linux_x64.tar.gz
                     * 
                     * LATEST VERSION: 2.3.30 (as of January 2025)
                     * See: https://github.com/Checkmarx/ast-cli/releases
                     * Direct download URL format: releases/download/{VERSION}/ast-cli_{VERSION}_linux_x64.tar.gz
                     * ------------------------------------------------------------------- */
                    // Check if CLI exists and is the correct version
                    def cliExists = fileExists("${CLI_DIR}/cx")
                    def cliVersion = null
                    
                    if (cliExists) {
                        try {
                            cliVersion = sh(script: "${CLI_DIR}/cx version", returnStdout: true).trim()
                            echo "Current CLI version: ${cliVersion}"
                        } catch (Exception e) {
                            echo "Could not determine CLI version: ${e.message}"
                            cliVersion = null
                        }
                    }
                    
                    // Download if CLI doesn't exist or version doesn't match
                    if (!cliExists || !cliVersion?.contains(params.CLI_VERSION)) {
                        dir(CLI_DIR) {
                            echo 'Downloading Checkmarx ONE CLI …'
                            
                            // Use the correct direct download URL format
                            def downloadUrl = "https://github.com/Checkmarx/ast-cli/releases/download/${params.CLI_VERSION}/ast-cli_${params.CLI_VERSION}_linux_x64.tar.gz"
                            
                            echo "Downloading from: ${downloadUrl}"
                            
                            sh """
                                # Download CLI with error checking
                                if curl -sL ${downloadUrl} -o cli.tgz; then
                                    echo "Download successful, extracting..."
                                    if tar -xzf cli.tgz; then
                                        echo "Extraction successful"
                                        rm cli.tgz
                                        
                                        # Verify CLI executable exists
                                        if [ -f "cx" ]; then
                                            echo "CLI executable found: cx"
                                            chmod +x cx
                                        else
                                            echo "ERROR: CLI executable 'cx' not found after extraction"
                                            ls -la
                                            exit 1
                                        fi
                                    else
                                        echo "ERROR: Failed to extract CLI archive"
                                        exit 1
                                    fi
                                else
                                    echo "ERROR: Failed to download CLI from ${downloadUrl}"
                                    exit 1
                                fi
                            """
                        }
                    } else {
                        echo "CLI version ${params.CLI_VERSION} already exists - skipping download"
                    }
                    
                    // Verify CLI is working and show version
                    try {
                        def actualVersion = sh(script: "${CLI_DIR}/cx version", returnStdout: true).trim()
                        echo "✓ CLI is working. Version: ${actualVersion}"
                    } catch (Exception e) {
                        echo "ERROR: CLI is not working properly: ${e.message}"
                        error("CLI verification failed")
                    }
                }
            }
        }

        stage('Clone Repository') {
            steps {
                script {
                    def repoOwner = params.REPO_OWNER
                    def repoName = params.REPO_NAME
                    def releaseTag = params.BRANCH_OR_TAG
                    def githubToken = params.GITHUB_API_KEY
                    
                    echo "Cloning repository: ${repoOwner}/${repoName} (branch: ${releaseTag})"
                    
                                        /* Clean previous contents and preserve CLI by backing it up */
                    sh """
                        # Backup the CLI directory
                        if [ -d "${CLI_DIR}" ]; then
                            echo "Backing up CLI directory..."
                            cp -r ${CLI_DIR} /tmp/${CLI_DIR}_backup
                        fi
                        
                        # Remove everything including hidden files
                        rm -rf ./* ./.* 2>/dev/null || true
                        
                        # Ensure we're in a clean state
                        if [ -d ".git" ]; then
                            echo "Removing existing .git directory..."
                            rm -rf .git
                        fi
                        
                        # Restore the CLI directory
                        if [ -d "/tmp/${CLI_DIR}_backup" ]; then
                            echo "Restoring CLI directory..."
                            cp -r /tmp/${CLI_DIR}_backup ${CLI_DIR}
                            rm -rf /tmp/${CLI_DIR}_backup
                        fi
                        
                        # Verify clean state
                        echo "Current directory contents after cleanup:"
                        ls -la
                    """
                    
                    /* Clone the repository using the GitHub API key for authentication */
                    def cloneUrl = "https://${githubToken}@github.com/${repoOwner}/${repoName}.git"
                    
                    try {
                        echo "Attempting to clone repository..."
                        sh """
                            # Clone to a temporary directory first, then move contents
                            TEMP_DIR=\$(mktemp -d)
                            echo "Using temporary directory: \$TEMP_DIR"
                            
                            # First try to clone with branch specification
                            if git clone --depth 1 --branch ${releaseTag} ${cloneUrl} \$TEMP_DIR 2>/dev/null; then
                                echo "Successfully cloned branch ${releaseTag}"
                            else
                                echo "Branch ${releaseTag} not found, cloning default branch..."
                                git clone --depth 1 ${cloneUrl} \$TEMP_DIR
                                echo "Checking out requested branch/tag: ${releaseTag}"
                                cd \$TEMP_DIR
                                git checkout ${releaseTag} 2>/dev/null || echo "Warning: Could not checkout ${releaseTag}, using default branch"
                                cd -
                            fi
                            
                            # Move contents from temp dir to current directory
                            echo "Moving repository contents to workspace..."
                            cp -r \$TEMP_DIR/* \$TEMP_DIR/.* . 2>/dev/null || true
                            
                            # Clean up temp directory
                            rm -rf \$TEMP_DIR
                            
                            echo "Repository contents moved successfully"
                        """
                        echo "Repository cloned successfully"
                        
                        // Debug: Show what's in the workspace after cloning
                        echo "DEBUG: Workspace contents after cloning:"
                        sh "ls -la"
                        echo "DEBUG: Git status:"
                        sh "git status --porcelain"
                    } catch (Exception e) {
                        echo "ERROR: Failed to clone repository: ${e.message}"
                        error("Repository cloning failed. Please check your GitHub API key and repository access.")
                    }
                }
            }
        }

        stage('Scan Repository') {
            steps {
                script {
                    def repoOwner = params.REPO_OWNER
                    def repoName = params.REPO_NAME
                    def releaseTag = params.BRANCH_OR_TAG
                    def cxApiKey = params.CX_API_KEY
                    
                    echo "Starting security scan for ${repoOwner}/${repoName} (${releaseTag})"
                    
                    /* ------------------------------------------------------------------
                     * Execute the scan command with enhanced parameters
                     * ------------------------------------------------------------------ */
                    // Use absolute path to CLI since we're in the cloned repo directory
                    def cliCmd = "${env.WORKSPACE}/${CLI_DIR}/cx"
                    def quote = "'"
                    
                    // Debug: Verify CLI path and permissions
                    echo "DEBUG: CLI path: ${cliCmd}"
                    echo "DEBUG: Current directory: ${pwd()}"
                    echo "DEBUG: Workspace: ${env.WORKSPACE}"
                    
                    // Check if CLI directory exists
                    if (!fileExists("${env.WORKSPACE}/${CLI_DIR}")) {
                        echo "ERROR: CLI directory not found at ${env.WORKSPACE}/${CLI_DIR}"
                        echo "Current directory: ${pwd()}"
                        echo "Workspace: ${env.WORKSPACE}"
                        error("CLI directory not found in workspace")
                    }
                    
                    echo "DEBUG: CLI directory contents:"
                    sh "ls -la ${env.WORKSPACE}/${CLI_DIR}/"
                    echo "DEBUG: CLI executable check:"
                    sh "file ${env.WORKSPACE}/${CLI_DIR}/cx"
                    
                    // Ensure CLI exists in the workspace
                    if (!fileExists("${env.WORKSPACE}/${CLI_DIR}/cx")) {
                        echo "ERROR: CLI executable not found at ${env.WORKSPACE}/${CLI_DIR}/cx"
                        echo "Current directory: ${pwd()}"
                        echo "Workspace: ${env.WORKSPACE}"
                        error("CLI executable not found in workspace")
                    }
                    
                    // First, let's check what flags are available for this CLI version
                    echo "DEBUG: Checking available CLI flags..."
                    sh "${cliCmd} scan create --help | head -50"
                    
                    // Build the scan command with proper flags based on Checkmarx documentation
                    def scanCmd = "${cliCmd} scan create --project-name ${quote}Compliance/${repoOwner}/${repoName}/${releaseTag}${quote} " +
                                  "-s ${params.SOURCE_PATH} --branch ${quote}${releaseTag}${quote} --branch-primary --tags ${quote}release:${releaseTag}${quote} " +
                                  "--debug " +
                                  "--report-format ${params.CX_REPORT_FORMAT} " +
                                  "--timeout ${params.CX_SCAN_TIMEOUT} " +
                                  "--apikey ${cxApiKey}"
                    
                    // Add thresholds if specified
                    if (params.CX_THRESHOLDS?.trim()) {
                        scanCmd += " --threshold ${quote}${params.CX_THRESHOLDS}${quote}"
                        echo "DEBUG: Added thresholds: ${params.CX_THRESHOLDS}"
                    }
                    
                    // Add PDF-specific flags for email and sections
                    if (params.CX_REPORT_FORMAT == 'pdf') {
                        scanCmd += " --report-pdf-email ${quote}${params.EMAIL_RECIPIENT}${quote}"
                        scanCmd += " --report-pdf-options ${quote}${params.CX_PDF_SECTIONS}${quote}"
                        echo "DEBUG: Added PDF email recipient: ${params.EMAIL_RECIPIENT}"
                        echo "DEBUG: Added PDF sections: ${params.CX_PDF_SECTIONS}"
                    }
                    
                    echo "DEBUG: Using correct Checkmarx CLI flags based on official documentation"
                    
                    echo "DEBUG: Executing scan command: ${scanCmd}"
                    
                    def scanOut
                    try {
                        // Execute scan with timeout to prevent hanging
                        scanOut = sh(script: "timeout ${params.CX_SCAN_TIMEOUT} ${scanCmd}", returnStdout: true).trim()
                    } catch (Exception e) {
                        if (e.message.contains('timeout')) {
                            error("Security scan timed out after ${params.CX_SCAN_TIMEOUT} seconds. Consider increasing the timeout value.")
                        } else {
                            echo "ERROR: Scan command failed: ${e.message}"
                            error("Security scan failed. Please check your Checkmarx ONE API key and configuration.")
                        }
                    }
                    
                    // Try to extract scanId: first look for JSON, else fall back to UUID pattern
                    String scanId
                    String projectId = null
                    def jsonLine = scanOut.readLines().reverse().find { it.trim().startsWith('{') }
                    if(jsonLine) {
                        def js = new groovy.json.JsonSlurper().parseText(jsonLine)
                        scanId    = js.id
                        projectId = js.projectId ?: js.projectID ?: null
                    } else {
                        def m = (scanOut =~ /[0-9a-fA-F-]{36}/)
                        if (m) scanId = m[0]
                    }
                    
                    if(!scanId) {
                        echo "Warning: Unable to parse scan ID from CLI output"
                    } else {
                        echo "✔︎  Scan ${scanId} completed successfully for ${repoOwner}/${repoName}"
                        if (projectId) {
                            echo "Project ID: ${projectId}"
                        }
                    }
                    
                    echo "Scan completed successfully!"
                }
            }
        }
    }

    post {
        always {
            echo 'Pipeline completed!'
        }
        success {
            echo 'Security scan completed successfully!'
        }
        failure {
            echo 'Security scan failed!'
        }
    }
}

