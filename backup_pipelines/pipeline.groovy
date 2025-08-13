pipeline {
    /* 
     * ========================================================================
     * CHECKMARX ONE COMPLIANCE PIPELINE
     * ========================================================================
     * 
     * PURPOSE: This pipeline automates security scanning across multiple repositories
     *          in a GitHub organization for a specific branch/tag. It downloads the
     *          Checkmarx ONE CLI, scans repositories, and generates consolidated reports.
     * 
     * WORKFLOW:
     * 1. Prepare: Download and setup Checkmarx ONE CLI
     * 2. Find Repos: Identify repositories containing the target branch/tag
     * 3. Scan Repositories: Run security scans in parallel
     * 4. Generate Reports: Create consolidated PDF reports
     * 
     * PREREQUISITES:
     * - Jenkins credentials: 'github-pat' (GitHub Personal Access Token)
     * - Jenkins credentials: 'cx-api-key' (Checkmarx ONE API Key)
     * - Jenkins plugins: Email Extension (for notifications)
     * 
     * AUTHOR: Sean Carroll
     * LAST UPDATED: 2025
     * ========================================================================
     */
    
    /* ---------- GLOBAL CONFIG ---------- */
    agent any
    // options { ansiColor('xterm') } // (only if you later add the plugin)

    parameters {
        /* 
         * PIPELINE PARAMETERS
         * These parameters allow users to customize the pipeline behavior
         * without modifying the code. They appear in the Jenkins UI.
         */
        booleanParam(name: 'DEBUG', defaultValue: false, description: 'Enable verbose debugging output')
        string(
            name: 'REPO_NAME',
            defaultValue: 'SampleJenkins',
            description: 'Repository name to scan'
        )
        string(
            name: 'REPO_OWNER',
            defaultValue: 'CxSeanOrg2',
            description: 'Repository owner/organization'
        )
        string(
            name: 'BRANCH_OR_TAG',
            defaultValue: 'v3',
            description: 'Release branch or tag to scan'
        )
        string(
            name: 'SOURCE_PATH',
            defaultValue: '.',
            description: 'Source path to scan (default: current directory)'
        )
        string(
            name: 'EMAIL_RECIPIENT',
            defaultValue: 'Sean.Carroll@checkmarx.com',
            description: 'Email address to receive consolidated reports'
        )
        string(
            name: 'CLI_VERSION',
            defaultValue: '2.3.31',
            description: 'Checkmarx ONE CLI version to download (latest: 2.3.31)'
        )
        string(
            name: 'CRON_SCHEDULE',
            defaultValue: 'H 0 * * 0',
            description: 'Cron schedule for automated runs (e.g., H 0 * * 0 = every Sunday)'
        )

        string(
            name: 'CX_BASE_URL',
            defaultValue: 'https://ast.checkmarx.net',
            description: 'Checkmarx ONE base URL'
        )
        string(
            name: 'CX_IAM_URL',
            defaultValue: 'https://iam.checkmarx.net',
            description: 'Checkmarx IAM URL for OAuth token requests'
        )
        string(
            name: 'CX_OAUTH_CLIENT_ID',
            defaultValue: 'ast-app',
            description: 'OAuth client ID for Checkmarx ONE API authentication'
        )
        string(
            name: 'CX_REPORT_FORMAT',
            defaultValue: 'pdf',
            description: 'Report format (pdf, html, json, sarif, sonar, markdown)'
        )
        string(
            name: 'CX_DEFAULT_TENANT',
            defaultValue: 'workshop',
            description: 'Default Checkmarx ONE tenant (used if not found in API key)'
        )
        string(
            name: 'CX_SCAN_TIMEOUT',
            defaultValue: '3600',
            description: 'Scan timeout in seconds (default: 1 hour)'
        )
    }

    /* Run on schedule defined by CRON_SCHEDULE parameter */
    triggers { 
        cron(params.CRON_SCHEDULE ?: 'H 0 * * 0') 
    }

    environment {
        /* 
         * ENVIRONMENT VARIABLES
         * These define paths and settings used throughout the pipeline
         */
        
        /* Folder where we cache the CLI per agent OS */
        CLI_DIR   = 'CxONE_CLI'

        /* Persistence file that survives pipeline restarts */
        STATUS_DB = '.scan_status.json'
        /* File to persist list of repos requiring scan */
        REPOS_FILE = '.repos_to_scan.json'

        /* Polling controls (5 min × 12 h max) */
        POLL_INTERVAL  = 300
        MAX_ITERATIONS = 144
    }

    /* Bind secrets from Jenkins credentials store */
    /*  - ‘github-pat’  : Secret Text  (GitHub PAT)
       - ‘cx-api-key’ : Secret Text  (Checkmarx ONE API key) */
    stages {
        stage('Prepare') {
            steps {
                withCredentials([
                    string(credentialsId: 'github-pat',  variable: 'GITHUB_TOKEN'),
                    string(credentialsId: 'cx-api-key',  variable: 'CX_API_KEY')
                ]) {
                    script {


                        /* Propagate debug flag to env so helper functions can read it */
                        env.DEBUG = params.DEBUG.toString()
                        
                        /* Log parameter values for debugging */
                        echo "Using repository: ${params.REPO_OWNER}/${params.REPO_NAME}"
                        echo "Using branch/tag: ${params.BRANCH_OR_TAG}"
                        echo "Using source path: ${params.SOURCE_PATH}"
                        echo "Using email recipient: ${params.EMAIL_RECIPIENT}"
                        echo "Using CLI version: ${params.CLI_VERSION}"
                        echo "Using cron schedule: ${params.CRON_SCHEDULE}"
                        echo "Using Checkmarx base URL: ${params.CX_BASE_URL}"
                        echo "Using Checkmarx IAM URL: ${params.CX_IAM_URL}"
                        echo "Using OAuth client ID: ${params.CX_OAUTH_CLIENT_ID}"
                        echo "Using report format: ${params.CX_REPORT_FORMAT}"
                        echo "Using default tenant: ${params.CX_DEFAULT_TENANT}"
                        echo "Using scan timeout: ${params.CX_SCAN_TIMEOUT} seconds"

                        /* -------------------------------------------------------------------
                         * CLI DOWNLOAD SECTION
                         * 
                         * PURPOSE: Download and extract the Checkmarx ONE CLI tool
                         * 
                         * LOGIC:
                         * - Check if CLI already exists to avoid re-downloading
                         * - Download from GitHub releases based on OS (Linux/Windows)
                         * - Extract the archive and clean up temporary files
                         * - Cache the CLI in workspace for reuse across builds
                         * 
                         * DOWNLOAD URL:
                         * - Linux: https://github.com/Checkmarx/ast-cli/releases/download/{VERSION}/ast-cli_{VERSION}_linux_x64.tar.gz
                         * 
                         * LATEST VERSION: 2.3.31 (as of January 2025)
                         * See: https://github.com/Checkmarx/ast-cli/releases
                         * ------------------------------------------------------------------- */
                        // Check if CLI exists and is the correct version
                        def cliExists = fileExists("${CLI_DIR}/cx")
                        def cliVersion = null
                        
                        if (cliExists) {
                            try {
                                cliVersion = sh(script: "${CLI_DIR}/cx version", returnStdout: true).trim()
                                debug("Current CLI version: ${cliVersion}")
                            } catch (Exception e) {
                                debug("Could not determine CLI version: ${e.message}")
                                cliVersion = null
                            }
                        }
                        
                        // Download if CLI doesn't exist or version doesn't match
                        if (!cliExists || !cliVersion?.contains(params.CLI_VERSION)) {
                            dir(CLI_DIR) {
                                echo 'Downloading Checkmarx ONE CLI …'
                                sh """
                                    curl -sL \\
                                      https://github.com/Checkmarx/ast-cli/releases/download/${params.CLI_VERSION}/ast-cli_${params.CLI_VERSION}_linux_x64.tar.gz \\
                                      -o cli.tgz
                                    tar -xzf cli.tgz
                                    rm cli.tgz
                                """
                            }
                        } else {
                            echo "CLI version ${params.CLI_VERSION} already exists - skipping download"
                        }
                    }
                }
            }
        }

        stage('Prepare Repository') {
            steps {
                withCredentials([
                    string(credentialsId: 'github-pat', variable: 'GITHUB_TOKEN'),
                    string(credentialsId: 'cx-api-key', variable: 'CX_API_KEY')
                ]) {
                    script {
                        def repoOwner = params.REPO_OWNER
                        def repoName = params.REPO_NAME
                        def releaseTag = params.BRANCH_OR_TAG
                        debug("Using repository: ${repoOwner}/${repoName}")

                        /* --------------------------------------------------------------
                         * For single repository scanning, we don't need to search org
                         * -------------------------------------------------------------- */
                        def selectedRepos = [repoName]

                        writeFile file: env.REPOS_FILE, text: selectedRepos.join('\n')

                        debug("Selected repos: ${selectedRepos}")
                        if (selectedRepos) {
                            echo "Repository that will be scanned for tag/branch '${releaseTag}':"
                            selectedRepos.each { r -> echo " - ${r}" }
                        } else {
                            echo "No repository specified."
                        }
                        echo "Found ${selectedRepos.size()} repository with tag/branch '${releaseTag}'."
                    }
                }
            }
        }

        /* ------------------------------------------------------------------
         * Stage: Scan Repositories in parallel
         * ------------------------------------------------------------------ */
        stage('Scan Repositories') {
            when { expression { fileExists(env.REPOS_FILE) } }
            steps {
                withCredentials([
                    string(credentialsId: 'github-pat', variable: 'GITHUB_TOKEN'),
                    string(credentialsId: 'cx-api-key', variable: 'CX_API_KEY')
                ]) {
                    script {
                        def repoOwner   = params.REPO_OWNER
                        def releaseTag  = params.BRANCH_OR_TAG
                        def reposList   = readFile(env.REPOS_FILE).split('\r?\n').findAll { it?.trim() }

                        debug("Repos to scan: ${reposList}")

                        if (!reposList) {
                            echo 'No repositories to scan.'
                            return
                        }



                        def statusDb = loadStatus()
                        debug("Loaded status DB keys: ${statusDb.keySet()}")
                        def tasks    = [:]

                        def cliCmd   = "\"${env.WORKSPACE}/${CLI_DIR}/cx\""

                        reposList.each { repoName ->
                            def key = "${repoName}|${releaseTag}"
                            if (statusDb[key]?.status == 'Completed') {
                                echo "✔︎  ${key} already scanned – skipping"
                                return
                            }

                            tasks[key] = {
                                dir("${repoName}_${releaseTag}") {
                                    /* Clean previous contents if this directory was used in an earlier build */
                                    deleteDir()

                                    try {
                                        /* -------------------- Clone repo -------------------- */
                                        def cloneUrl = "https://github.com/${repoOwner}/${repoName}.git"
                                        sh """
                                            git clone --depth 1 --branch ${releaseTag} ${cloneUrl} . \
                                                || git clone --depth 1 ${cloneUrl} . && git checkout ${releaseTag}
                                        """

                                        /* -------------------- Trigger scan ------------------- */
                                        def quote = "'"
                                        
                                        // Execute the scan command with Jenkins secret API key and tags
                                        def scanOut
                                        def apiParam = "--apikey \$CX_API_KEY"
                                        
                                        def scanCmd = "${cliCmd} scan create --project-name ${quote}Compliance/${params.REPO_OWNER}/${params.REPO_NAME}/${releaseTag}${quote} " +
                                                      "-s ${params.SOURCE_PATH} --branch ${quote}${releaseTag}${quote} --branch-primary --tags ${quote}release:${releaseTag}${quote} " +
                                                      "--debug " +
                                                      "--report-email ${params.EMAIL_RECIPIENT} --report-format ${params.CX_REPORT_FORMAT} " +
                                                      "--timeout ${params.CX_SCAN_TIMEOUT} " +
                                                      apiParam
                                        echo "DEBUG: Executing scan command: ${scanCmd}"
                                        scanOut = sh(script: scanCmd, returnStdout: true).trim()

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
                                        if(!scanId) throw new Exception("Unable to parse scan ID from CLI output for ${key}")
                                        echo "✔︎  Scan ${scanId} finished for ${key} (the CLI blocks until completion)"

                                        statusDb[key] = [
                                            repo   : repoName,
                                            tag    : releaseTag,
                                            scanId : scanId,
                                            projectId : projectId,
                                            status : 'Completed'
                                        ]
                                    } catch (e) {
                                        statusDb[key] = [ repo: repoName, tag: releaseTag,
                                                          status: 'Failed', error: e.toString() ]
                                        echo "✖︎  Scan failed for ${key}: ${e}"
                                    }
                                }
                            }
                        }

                        if (tasks) { parallel tasks }
                        else       { echo 'Nothing to scan after filtering.' }

                        saveStatus(statusDb)
                    }
                }
            }
        }

        stage('Generate Consolidated PDF') {
            when { expression { fileExists(STATUS_DB) } }
            steps {
                withCredentials([
                    string(credentialsId: 'cx-api-key', variable: 'CX_API_KEY')
                ]) {
                    script {
                        def statusDb = loadStatus()
                        def completed = statusDb.findAll { k,v -> v.status == 'Completed' }
                        if (!completed) {
                            echo 'No finished scans – skipping report.'
                            return
                        }
                        
                        echo "Generating consolidated report for ${completed.size()} completed scans..."
                        echo "Reports will be sent via email to: ${params.EMAIL_RECIPIENT}"
                        
                        // The CLI handles email delivery automatically via --report-email parameter
                        // No additional email notification needed
                        
                        echo "[OK] Consolidated report generation completed successfully"
                    }
                }
            }
        }
    }

    post {
        always { echo '[FINISH] Compliance pipeline finished.' }
    }
}

/* ------------------------------------------------------------------------ */
/* ---------------------------- Helper methods ---------------------------- */
/* ------------------------------------------------------------------------ */

/* Lightweight HTTP JSON wrapper */
// Extended: extraHeaders allows us to include Accept or other headers; authHeader may be null
def httpJson(String url, String authHeader=null, String method = 'GET', String body=null, Map extraHeaders=[:]) {
    if (isUnix()) {
        def cmd = [ 'curl', '-s', '-X', method ]
        if (authHeader) {
            cmd << "-H 'Authorization: ${authHeader}'"
        }
        extraHeaders.each { k,v -> cmd << "-H '${k}: ${v}'" }
        cmd << "-H 'Content-Type: application/json'"
        cmd << url
        if (body) {
            cmd.add(cmd.size()-1, '-d')
            cmd.add(cmd.size()-1, body.replace('"', '\"'))
        }
        // Redact the auth header before printing to avoid Jenkins warnings
        def curlCmd = cmd.collect { it.startsWith('-H') && it.contains('Authorization:') ? '-H Authorization: ***' : it }.join(' ')
        debug("curl command: ${curlCmd}")
        def raw
        try {
            raw = sh(script: curlCmd, returnStdout: true).trim()
        } catch (err) {
            echo "\u001B[31mERROR executing curl: ${err}\u001B[0m"
            echo "Command was: ${curlCmd}"
            throw err
        }
        debug("Response from ${url}: ${raw.take(500)} …")
        return toSerializable( safeParse(raw) )
    } else {
        // Build PowerShell script line-by-line to avoid Groovy/DSL parsing issues
        def encodedBody = body ? body.replace("'", "''") : ''
        def psLines = []
        psLines << "\$ProgressPreference='SilentlyContinue'"
        def headerPairs = []
        
        // Handle Content-Type header - use custom one if provided, otherwise default
        def contentType = extraHeaders['Content-Type'] ?: 'application/json'
        headerPairs << "'Content-Type'='${contentType}'"
        
        if (authHeader) headerPairs << "Authorization='${authHeader}'"
        extraHeaders.each { k,v -> 
            if (k != 'Content-Type') { // Skip Content-Type as we already handled it
                headerPairs << "'${k}'='${v}'" 
            }
        }
        psLines << "\$headers = @{ ${headerPairs.join('; ')} }"
        if (body) {
            psLines << "\$body = @'\n${encodedBody}\n'@"
        }
        def restLine = "Invoke-RestMethod -Uri '${url}' -Headers \$headers -Method ${method} " + (body ? '-Body \$body' : '')
        psLines << "\$result = ${restLine}"
        psLines << "\$result | ConvertTo-Json -Compress"
        def ps = psLines.join('; ')
        
        debug("Invoke-RestMethod to ${url} (method: ${method})")
        // Remove the Authorization line before echoing
        def safePs = ps.replaceAll('Authorization=.*?;','Authorization=***;')
        debug("PowerShell script =>\n${safePs}")
        def raw
        try {
            raw = powershell(script: ps, returnStdout: true).trim()
        } catch (err) {
            echo "\u001B[31mERROR executing PowerShell Invoke-RestMethod: ${err}\u001B[0m"
            echo "Script content was:\n${ps}"
            throw err
        }
        debug("Response from ${url}: ${raw.take(500)} …")
        return toSerializable( safeParse(raw) )
    }
}

/* Download binary (e.g., PDF) without relying on curl on Windows */
def downloadFile(String url, String filePath, String authHeader = null, Map extraHeaders = [:]) {
    if (isUnix()) {
        debug("Downloading file via curl to ${filePath} from ${url}")
        try {
            def headers = []
            if (authHeader) headers << "-H 'Authorization: ${authHeader}'"
            extraHeaders.each { k,v -> headers << "-H '${k}: ${v}'" }
            def headerStr = headers.join(' ')
            sh "curl -s -L ${headerStr} ${url} -o ${filePath}"
        } catch (err) {
            echo "\u001B[31mERROR downloading file via curl: ${err}\u001B[0m"
            throw err
        }
    } else {
        debug("Downloading file via curl.exe to ${filePath} from ${url}")
        def headers = []
        if (authHeader) headers << "-H \"Authorization: ${authHeader}\""
        extraHeaders.each { k,v -> headers << "-H \"${k}: ${v}\"" }
        def headerStr = headers.join(' ')
        // First try curl.exe from the well-known system location (skip fileExists check – just try it)
        try {
            // Escape % characters in URL for Windows batch processing
            def escapedUrl = url.replace('%', '%%')
            def cmd = "%SystemRoot%\\SysNative\\curl.exe -s -L ${headerStr} \"${escapedUrl}\" -o \"${filePath}\" ^|^| %SystemRoot%\\System32\\curl.exe -s -L ${headerStr} \"${escapedUrl}\" -o \"${filePath}\""
            bat(script: cmd)
            return // success
        } catch (err) {
            echo "[WARN] curl.exe download failed (${err.message}) – falling back to Invoke-WebRequest"
        }

        // Fallback: PowerShell download
        def psLines = []
        psLines << "\$ProgressPreference='SilentlyContinue'"
        def headerPairs = []
        if (authHeader) headerPairs << "Authorization='${authHeader}'"
        extraHeaders.each { k,v -> headerPairs << "'${k}'='${v}'" }
        psLines << "\$headers = @{ ${headerPairs.join('; ')} }"

        // Use Invoke-WebRequest with increased redirection limit and direct download
        psLines << "Invoke-WebRequest -Uri '${url}' -Headers \$headers -Method Get -MaximumRedirection 10 -UseBasicParsing -OutFile '${filePath}'"
        def ps = psLines.join('; ')
        try {
            powershell(script: ps)
        } catch (err) {
            echo "\u001B[31mERROR downloading file via Invoke-WebRequest: ${err}\u001B[0m"
            echo "Script content was:\n${ps}"
            throw err
        }
    }
}

/* Poll any endpoint until extractor(js) == targetStatus */
def waitFor(url, targetStatus, extractor, headerName, headerVal) {
    for (int i = 0; i < env.MAX_ITERATIONS.toInteger(); i++) {
        def js = httpJson(url, headerVal)
        if (extractor(js).toString().equalsIgnoreCase(targetStatus)) return
        sleep env.POLL_INTERVAL.toInteger()
    }
    error "Timed-out waiting for ${url}"
}

/* Load / save status DB without plugins */
def loadStatus() {
    def m = [:]
    if (fileExists(STATUS_DB)) {
        readFile(STATUS_DB).split('\\r?\\n').each { line ->
            if (!line) return
            def parts = line.split('=', 2)
            if (parts.size() == 2) {
                def key = parts[0]
                def rest = parts[1].split('\\|', 3)
                def scan = rest.size() > 0 ? rest[0] : ''
                def status = rest.size() > 1 ? rest[1] : ''
                def proj = rest.size() > 2 ? rest[2] : ''
                m[key] = [ scanId: scan, status: status, projectId: proj ]
            }
        }
    }
    return m
}

def saveStatus(m) {
    def lines = m.collect { k, v -> "${k}=${v.scanId ?: ''}|${v.status}|${v.projectId ?: ''}" }
    writeFile file: STATUS_DB, text: lines.join('\n')
}

/* Simple conditional logger */
def debug(msg) {
    if (env.DEBUG?.toBoolean()) {
        echo "\u001B[36mDEBUG: ${msg}\u001B[0m" // cyan for visibility
    }
}

/* Convert LazyMap / GPathResult into plain LinkedHashMap so it’s Serializable */
@NonCPS
def toSerializable(obj) {
    if (obj instanceof Map) {
        def m = [:]
        obj.each { k, v -> m[k] = toSerializable(v) }
        return m
    }
    if (obj instanceof Collection) {
        return obj.collect { v -> toSerializable(v) }
    }
    return obj
}

def safeParse(raw) {
    if (!raw?.trim()) return []          // or [:] if you expect an object
    new groovy.json.JsonSlurper().parseText(raw)
}

/* ------------------------------------------------------------- */
        /* Extract tenant name from API key */
        def extractTenantFromApiKey(String apiKey) {
            // Try to extract tenant from JWT token without using decodeBase64
            try {
                // API keys are often JWT tokens that contain tenant info
                def parts = apiKey.split('\\.')
                if (parts.length >= 2) {
                    def payload = parts[1]

                    // Use shell command to decode base64 (sandbox-safe)
                    def decoded
                    if (isUnix()) {
                        decoded = sh(script: "echo '${payload}' | base64 -d", returnStdout: true).trim()
                    } else {
                        // Write to temp file and decode (certutil needs input/output files)
                        writeFile file: 'temp_payload.txt', text: payload
                        // Remove existing output file if it exists and decode
                        decoded = bat(script: "if exist temp_decoded.txt del temp_decoded.txt && certutil -decode temp_payload.txt temp_decoded.txt", returnStdout: true).trim()
                        decoded = readFile('temp_decoded.txt').trim()
                        
                        // Clean up temporary files immediately
                        bat(script: "if exist temp_payload.txt del temp_payload.txt && if exist temp_decoded.txt del temp_decoded.txt", returnStdout: true)
                    }

                    def json = new groovy.json.JsonSlurper().parseText(decoded)

                    // Look for tenant in common JWT fields
                    if (json.tenant) return json.tenant
                    if (json.realm) return json.realm
                    if (json.iss && json.iss.contains('/realms/')) {
                        def realmMatch = json.iss =~ /\/realms\/([^\/]+)/
                        if (realmMatch) return realmMatch[0][1]
                    }
                }
            } catch (Exception e) {
                debug("Could not extract tenant from API key: ${e.message}")
            }

            // Fallback: try to extract from API key format or use parameter
            if (apiKey.contains('workshop')) return 'workshop'
            if (apiKey.contains('ast-realm')) return 'ast-realm'
            if (apiKey.contains('ast-app')) return 'ast-app'

            // Default fallback: use parameter or default to workshop
            return params.CX_DEFAULT_TENANT ?: 'workshop'
        }

/* Retrieve short-lived OAuth access token using API key */
def getCxAccessToken(String apiKey) {
    def tenant = extractTenantFromApiKey(apiKey)
    debug("Extracted tenant: ${tenant}")
    def tokenUrl = "${params.CX_IAM_URL}/auth/realms/${tenant}/protocol/openid-connect/token"
    
    if (isUnix()) {
        def cmd = "curl -s -L -X POST -H 'Content-Type: application/x-www-form-urlencoded' -d 'grant_type=refresh_token&client_id=${params.CX_OAUTH_CLIENT_ID}&refresh_token=${apiKey}' ${tokenUrl}"
        def raw = sh(script: cmd, returnStdout: true).trim()
        return new groovy.json.JsonSlurper().parseText(raw).access_token
    } else {
        def curlPath = env.SystemRoot + "\\System32\\curl.exe"
        String raw
        if (fileExists(curlPath)) {
            def cmd = "${curlPath} -s -L -X POST -H \"Content-Type: application/x-www-form-urlencoded\" -d \"grant_type=refresh_token&client_id=${params.CX_OAUTH_CLIENT_ID}&refresh_token=%CX_API_KEY%\" \"${tokenUrl}\""
            raw = bat(script: cmd, returnStdout: true).trim()
        } else {
            /* Fall back to PowerShell Invoke-RestMethod */
            def ps = """
 \$ProgressPreference='SilentlyContinue';
 \$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
 \$headers.Add("Content-Type", "application/x-www-form-urlencoded")
 \$body = "grant_type=refresh_token&client_id=${params.CX_OAUTH_CLIENT_ID}&refresh_token=" + \$Env:CX_API_KEY
 try {
     \$resp = Invoke-RestMethod -Uri '${tokenUrl}' -Method Post -Headers \$headers -Body \$body -MaximumRedirection 5 -ErrorAction Stop;
     \$resp | ConvertTo-Json -Compress
 } catch {
     Write-Error "Token request failed: \$(\$_.Exception.Message)"
     exit 1
 }
 """
            raw = powershell(script: ps, returnStdout: true).trim()
        }
        return new groovy.json.JsonSlurper().parseText(raw).access_token
    }
}