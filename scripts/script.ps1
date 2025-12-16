param(
    [Parameter(Mandatory)][string]$accountName,
    [Parameter(Mandatory)][string]$adfName,
    [Parameter(Mandatory)][string]$adfPipelineName,
    [Parameter(Mandatory)][string]$adfPrincipalId,
    [Parameter(Mandatory)][string]$location,
    [Parameter(Mandatory)][string]$objectId,
    [Parameter(Mandatory)][string]$resourceGroupName,
    [Parameter(Mandatory)][string]$sqlDatabaseName,
    [Parameter(Mandatory)][string]$sqlSecretName,
    [Parameter(Mandatory)][string]$sqlServerAdminLogin,
    [Parameter(Mandatory)][string]$sqlServerName,
    [Parameter(Mandatory)][string]$storageAccountName,
    [Parameter(Mandatory)][string]$subscriptionId,
    [Parameter(Mandatory)][string]$vaultUri
)


# --------------------------------------------------------------------
# CRITICAL: Module Management for Az.Purview Strict Requirements
# Az.Purview 0.3.0 REQUIRES EXACTLY Az.Accounts 5.1.1
# --------------------------------------------------------------------
$ErrorActionPreference = 'Stop'

Write-Host "=== CRITICAL MODULE MANAGEMENT ===" -ForegroundColor Cyan
Write-Host "Az.Purview 0.3.0 requires EXACTLY Az.Accounts 5.1.1" -ForegroundColor Yellow
Write-Host "Preparing clean PowerShell environment..." -ForegroundColor Yellow

# Trust PSGallery
Write-Host "`nConfiguring PSGallery..." -ForegroundColor Cyan
try {
    Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted -ErrorAction Stop
    Write-Host "  ✓ PSGallery is trusted" -ForegroundColor Green
} catch {
    Write-Warning "Could not configure PSGallery: $_"
}

# Show what's currently loaded
Write-Host "`nCurrently loaded Az modules:" -ForegroundColor Cyan
$preLoadedModules = Get-Module Az.* 
if ($preLoadedModules) {
    $preLoadedModules | Format-Table Name, Version -AutoSize
} else {
    Write-Host "  (none)" -ForegroundColor Gray
}

# AGGRESSIVELY remove ALL Az modules from current session
Write-Host "`nRemoving ALL Az modules from session..." -ForegroundColor Yellow
Get-Module Az.* | ForEach-Object {
    Write-Host "  Removing: $($_.Name) v$($_.Version)" -ForegroundColor Gray
    Remove-Module $_.Name -Force -ErrorAction SilentlyContinue
}

# Verify all removed
$stillLoaded = Get-Module Az.*
if ($stillLoaded) {
    Write-Warning "Some modules still loaded: $($stillLoaded.Name -join ', ')"
} else {
    Write-Host "  ✓ All Az modules removed from session" -ForegroundColor Green
}

# Function to install and import exact version
function Install-ExactAzModule {
    param(
        [Parameter(Mandatory)][string]$ModuleName,
        [Parameter(Mandatory)][string]$RequiredVersion
    )
    
    Write-Host "`nProcessing: $ModuleName $RequiredVersion" -ForegroundColor Yellow
    
    # Check if exact version is installed
    $installedVersion = Get-Module -Name $ModuleName -ListAvailable | 
        Where-Object { $_.Version -eq [version]$RequiredVersion }
    
    if (-not $installedVersion) {
        Write-Host "  Installing $ModuleName $RequiredVersion..." -ForegroundColor Cyan
        try {
            Install-Module -Name $ModuleName `
                -RequiredVersion $RequiredVersion `
                -Repository PSGallery `
                -Scope CurrentUser `
                -AllowClobber `
                -Force `
                -SkipPublisherCheck `
                -ErrorAction Stop
            Write-Host "  ✓ Installed $ModuleName $RequiredVersion" -ForegroundColor Green
        } catch {
            Write-Error "Failed to install $ModuleName $RequiredVersion : $_"
            throw
        }
    } else {
        Write-Host "  ✓ $ModuleName $RequiredVersion already installed" -ForegroundColor Green
    }
    
    # Import the EXACT version
    Write-Host "  Importing $ModuleName $RequiredVersion..." -ForegroundColor Cyan
    try {
        Import-Module -Name $ModuleName `
            -RequiredVersion $RequiredVersion `
            -Global `
            -Force `
            -ErrorAction Stop
        
        $loaded = Get-Module -Name $ModuleName
        if ($loaded.Version -eq [version]$RequiredVersion) {
            Write-Host "  ✓ Successfully loaded $ModuleName v$($loaded.Version)" -ForegroundColor Green
        } else {
            throw "Wrong version loaded! Expected $RequiredVersion but got $($loaded.Version)"
        }
    } catch {
        Write-Error "Failed to import $ModuleName $RequiredVersion : $_"
        throw
    }
}

# Install and import modules in EXACT versions required by Az.Purview 0.3.0
Write-Host "`n=== Installing Required Module Versions ===" -ForegroundColor Cyan
Write-Host "This may take several minutes on first run..." -ForegroundColor Yellow

try {
    # Az.Accounts 5.1.1 is REQUIRED by Az.Purview 0.3.0
    Install-ExactAzModule -ModuleName 'Az.Accounts' -RequiredVersion '5.1.1'
    
    # Install compatible versions of other modules
    # These versions are compatible with Az.Accounts 5.1.1
    Install-ExactAzModule -ModuleName 'Az.Storage' -RequiredVersion '5.4.0'
    Install-ExactAzModule -ModuleName 'Az.DataFactory' -RequiredVersion '1.18.3'
    
    # Finally, install Az.Purview
    # Note: If Az.Purview still fails, we may need to use REST APIs instead
    Write-Host "`nAttempting to install Az.Purview 0.3.0..." -ForegroundColor Yellow
    Write-Host "(If this fails, we'll use REST API fallback)" -ForegroundColor Gray
    
    try {
        Install-ExactAzModule -ModuleName 'Az.Purview' -RequiredVersion '0.3.0'
    } catch {
        Write-Warning "Az.Purview installation failed: $_"
        Write-Host "Will use REST API methods instead of Az.Purview cmdlets" -ForegroundColor Yellow
        $script:UsePurviewRestApi = $true
    }
    
    Write-Host "`n=== Module Loading Complete ===" -ForegroundColor Green
    Write-Host "Final loaded modules:" -ForegroundColor Cyan
    Get-Module Az.* | Format-Table Name, Version, Path -AutoSize
    
} catch {
    Write-Error "CRITICAL: Failed to set up required modules: $_"
    Write-Host "`nDiagnostic Information:" -ForegroundColor Red
    Write-Host "Available Az.Accounts versions:" -ForegroundColor Yellow
    Get-Module Az.Accounts -ListAvailable | Format-Table Version, Path -AutoSize
    Write-Host "`nCurrently loaded modules:" -ForegroundColor Yellow
    Get-Module Az.* | Format-Table Name, Version -AutoSize
    throw
}

# --------------------------------------------------------------------
# End Module Management
# --------------------------------------------------------------------


# Variables
$pv_endpoint = "https://${accountName}.purview.azure.com"

function invokeWeb([string]$uri, [string]$access_token, [string]$method, [string]$body) { 
    $retryCount = 0
    $response = $null
    while (($null -eq $response) -and ($retryCount -lt 3)) {
        try {
            $response = Invoke-WebRequest -Uri $uri -Headers @{Authorization="Bearer $access_token"} -ContentType "application/json" -Method $method -Body $body
        }
        catch {
            Write-Host "[Error]"
            Write-Host "Token: ${access_token}"
            Write-Host "URI: ${uri}"
            Write-Host "Method: ${method}"
            Write-Host "Body: ${body}"
            Write-Host "Response:" $_.Exception.Response
            Write-Host "Exception:" $_.Exception
            $retryCount += 1
            $response = $null
            Start-Sleep 3
        }
    }
    Return $response.Content | ConvertFrom-Json -Depth 10
}

# [GET] Metadata Policy
function getMetadataPolicy([string]$access_token, [string]$collectionName) {
    $uri = "${pv_endpoint}/policystore/collections/${collectionName}/metadataPolicy?api-version=2021-07-01"
    $response = invokeWeb $uri $access_token "GET" $null
    Return $response
}

# Modify Metadata Policy
function addRoleAssignment([object]$policy, [string]$principalId, [string]$roleName) {
    Foreach ($attributeRule in $policy.properties.attributeRules) {
        if (($attributeRule.name).StartsWith("purviewmetadatarole_builtin_${roleName}:")) {
            Foreach ($conditionArray in $attributeRule.dnfCondition) {
                Foreach($condition in $conditionArray) {
                    if ($condition.attributeName -eq "principal.microsoft.id") {
                        $condition.attributeValueIncludedIn += $principalId
                    }
                 }
            }
        }
    }
}

# [PUT] Metadata Policy
function putMetadataPolicy([string]$access_token, [string]$metadataPolicyId, [object]$payload) {
    $uri = "${pv_endpoint}/policystore/metadataPolicies/${metadataPolicyId}?api-version=2021-07-01"
    $body = ($payload | ConvertTo-Json -Depth 10)
    $response = invokeWeb $uri $access_token "PUT" $body
    Return $response

}

# [PUT] Key Vault
function putVault([string]$access_token, [hashtable]$payload) {
    $randomId = -join (((48..57)+(65..90)+(97..122)) * 80 |Get-Random -Count 3 |ForEach-Object{[char]$_})
    $keyVaultName = "keyVault-${randomId}"
    $uri = "${pv_endpoint}/scan/azureKeyVaults/${keyVaultName}"
    $body = ($payload | ConvertTo-Json)
    $response = invokeWeb $uri $access_token "PUT" $body
    Return $response
}

# [PUT] Credential
function putCredential([string]$access_token, [hashtable]$payload) {
    $credentialName = $payload.name
    $uri = "${pv_endpoint}/proxy/credentials/${credentialName}?api-version=2020-12-01-preview"
    $body = ($payload | ConvertTo-Json -Depth 9)
    $response = invokeWeb $uri $access_token "PUT" $body
    Return $response
}

# [PUT] Scan
function putScan([string]$access_token, [string]$dataSourceName, [hashtable]$payload) {
    $scanName = $payload.name
    $uri = "${pv_endpoint}/scan/datasources/${dataSourceName}/scans/${scanName}"
    $body = ($payload | ConvertTo-Json -Depth 9)
    $response = invokeWeb $uri $access_token "PUT" $body
    Return $response
}

# [PUT] Run Scan
function runScan([string]$access_token, [string]$datasourceName, [string]$scanName) {
    $uri = "${pv_endpoint}/scan/datasources/${datasourceName}/scans/${scanName}/run?api-version=2018-12-01-preview"
    $payload = @{ scanLevel = "Full" }
    $body = ($payload | ConvertTo-Json)
    $response = invokeWeb $uri $access_token "POST" $body
    Return $response
}

# [POST] Create Glossary
function createGlossary([string]$access_token) {
    $uri = "${pv_endpoint}/catalog/api/atlas/v2/glossary"
    $payload = @{
        name = "Glossary"
        qualifiedName = "Glossary"
    }
    $body = ($payload | ConvertTo-Json -Depth 4)
    $response = invokeWeb $uri $access_token "POST" $body
    Return $response
}

# [POST] Import Glossary Terms
function importGlossaryTerms([string]$access_token, [string]$glossaryGuid, [string]$glossaryTermsTemplateUri) {
    $glossaryTermsFilename = "import-terms-sample.csv"
    Invoke-RestMethod -Uri $glossaryTermsTemplateUri -OutFile $glossaryTermsFilename
    $glossaryImportUri = "${pv_endpoint}/catalog/api/atlas/v2/glossary/${glossaryGuid}/terms/import?includeTermHierarchy=true&api-version=2021-05-01-preview"
    $fieldName = 'file'
    $filePath = (Get-Item $glossaryTermsFilename).FullName
    Add-Type -AssemblyName System.Net.Http
    $client = New-Object System.Net.Http.HttpClient
    $content = New-Object System.Net.Http.MultipartFormDataContent
    $fileStream = [System.IO.File]::OpenRead($filePath)
    $fileContent = New-Object System.Net.Http.StreamContent($fileStream)
    $content.Add($fileContent, $fieldName, $glossaryTermsFilename)
    $client.DefaultRequestHeaders.Authorization = New-Object System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", $access_token)
    $result = $client.PostAsync($glossaryImportUri, $content).Result
    return $result
}

# [PUT] Collection
function putCollection([string]$access_token, [string]$collectionFriendlyName, [string]$parentCollection) {
    $collectionName = -join ((97..122) | Get-Random -Count 6 | ForEach-Object {[char]$_})
    $uri = "${pv_endpoint}/account/collections/${collectionName}?api-version=2019-11-01-preview"
    $payload = @{
        "name" = $collectionName
        "parentCollection"= @{
            "type" = "CollectionReference"
            "referenceName" = $parentCollection
        }
        "friendlyName" = $collectionFriendlyName
    }
    $body = ($payload | ConvertTo-Json -Depth 10)
    $response = invokeWeb $uri $access_token "PUT" $body
    Return $response
}

# [PUT] Data Source
function putSource([string]$access_token, [hashtable]$payload) {
    $dataSourceName = $payload.name
    $uri = "${pv_endpoint}/scan/datasources/${dataSourceName}?api-version=2018-12-01-preview"
    $body = ($payload | ConvertTo-Json)
    $response = invokeWeb $uri $access_token "PUT" $body
    Return $response
}

Write-Host "`n=== Starting Purview Configuration ===" -ForegroundColor Cyan

# Add UAMI to Root Collection Admin
# Use cmdlet if available, otherwise use REST API
Write-Host "Adding managed identity to Purview root collection..." -ForegroundColor Yellow

if ($script:UsePurviewRestApi -eq $true) {
    Write-Host "Using REST API method (Az.Purview cmdlet unavailable)..." -ForegroundColor Yellow
    
    try {
        # Get management token
        $token = (Get-AzAccessToken -ResourceUrl "https://management.azure.com/").Token
        
        # Build the REST API URL
        $apiUrl = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.Purview/accounts/$accountName/addRootCollectionAdmin?api-version=2021-07-01"
        
        # Prepare request body
        $body = @{
            objectId = $objectId
        } | ConvertTo-Json
        
        # Make the REST API call
        $response = Invoke-RestMethod -Uri $apiUrl -Method Post -Headers @{
            'Authorization' = "Bearer $token"
            'Content-Type' = 'application/json'
        } -Body $body -ErrorAction Stop
        
        Write-Host "  ✓ Successfully added managed identity to root collection via REST API" -ForegroundColor Green
        
    } catch {
        Write-Error "Failed to add managed identity via REST API: $_"
        Write-Host "Response: $($_.Exception.Response)" -ForegroundColor Red
        throw
    }
    
} else {
    # Try using the Az.Purview cmdlet
    Write-Host "Using Az.Purview cmdlet..." -ForegroundColor Cyan
    
    $maxRetries = 3
    $retryCount = 0
    $success = $false

    while (-not $success -and $retryCount -lt $maxRetries) {
        try {
            $retryCount++
            Write-Host "Attempt $retryCount of $maxRetries..." -ForegroundColor Cyan
            
            # Verify the cmdlet is available
            $cmdlet = Get-Command Add-AzPurviewAccountRootCollectionAdmin -ErrorAction Stop
            Write-Host "  ✓ Cmdlet found: $($cmdlet.Source)" -ForegroundColor Green
            
            # Execute the command
            Add-AzPurviewAccountRootCollectionAdmin -AccountName $accountName -ResourceGroupName $resourceGroupName -ObjectId $objectId -ErrorAction Stop
            
            Write-Host "  ✓ Successfully added managed identity to root collection" -ForegroundColor Green
            $success = $true
            
        } catch {
            Write-Warning "  Attempt $retryCount failed: $_"
            
            if ($retryCount -lt $maxRetries) {
                Write-Host "  Waiting 10 seconds before retry..." -ForegroundColor Yellow
                Start-Sleep -Seconds 10
                
                # Try reimporting the module
                Write-Host "  Reimporting Az.Purview module..." -ForegroundColor Cyan
                Import-Module Az.Purview -Force -Global -ErrorAction SilentlyContinue
            } else {
                Write-Error "Failed to add managed identity to root collection after $maxRetries attempts"
                Write-Host "Falling back to REST API..." -ForegroundColor Yellow
                
                # Fallback to REST API
                try {
                    $token = (Get-AzAccessToken -ResourceUrl "https://management.azure.com/").Token
                    $apiUrl = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.Purview/accounts/$accountName/addRootCollectionAdmin?api-version=2021-07-01"
                    $body = @{ objectId = $objectId } | ConvertTo-Json
                    $response = Invoke-RestMethod -Uri $apiUrl -Method Post -Headers @{
                        'Authorization' = "Bearer $token"
                        'Content-Type' = 'application/json'
                    } -Body $body -ErrorAction Stop
                    Write-Host "  ✓ Successfully added managed identity via REST API fallback" -ForegroundColor Green
                    $success = $true
                } catch {
                    Write-Error "REST API fallback also failed: $_"
                    throw
                }
            }
        }
    }
}

# Get Access Token
$response = Invoke-WebRequest -Uri 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fpurview.azure.net%2F' -Headers @{Metadata="true"}
$content = $response.Content | ConvertFrom-Json
$access_token = $content.access_token

# 1. Update Root Collection Policy (Add Current User to Built-In Purview Roles)
$rootCollectionPolicy = getMetadataPolicy $access_token $accountName
addRoleAssignment $rootCollectionPolicy $objectId "data-curator"
addRoleAssignment $rootCollectionPolicy $objectId "data-source-administrator"
addRoleAssignment $rootCollectionPolicy $adfPrincipalId "data-curator"
$updatedPolicy = putMetadataPolicy $access_token $rootCollectionPolicy.id $rootCollectionPolicy

# 2. Refresh Access Token
$response = Invoke-WebRequest -Uri 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fpurview.azure.net%2F' -Headers @{Metadata="true"}
$content = $response.Content | ConvertFrom-Json
$access_token = $content.access_token

# 3. Create a Key Vault Connection
$vaultPayload = @{
    properties = @{
        baseUrl = $vaultUri
        description = ""
    }
}
$vault = putVault $access_token $vaultPayload

# 4. Create a Credential
$credentialPayload = @{
    name = "sql-cred"
    properties = @{
        description = ""
        type = "SqlAuth"
        typeProperties = @{
            password = @{
                secretName = $sqlSecretName
                secretVersion = ""
                store = @{
                    referenceName = $vault.name
                    type = "LinkedServiceReference"
                }
                type = "AzureKeyVaultSecret"
            }
            user = $sqlServerAdminLogin
        }
    }
    type = "Microsoft.Purview/accounts/credentials"
}
$cred = putCredential $access_token $credentialPayload

# 5. Create Collections (Sales and Marketing)
$collectionSales = putCollection $access_token "Sales" $accountName
$collectionMarketing = putCollection $access_token "Marketing" $accountName
$collectionSalesName = $collectionSales.name
$collectionMarketingName = $collectionMarketing.name
Start-Sleep 30

# 6. Create a Source (Azure SQL Database)
$sourceSqlPayload = @{
    id = "datasources/AzureSqlDatabase"
    kind = "AzureSqlDatabase"
    name = "AzureSqlDatabase"
    properties = @{
        collection = @{
            referenceName = $collectionSalesName
            type = 'CollectionReference'
        }
        location = $location
        resourceGroup = $resourceGroupName
        resourceName = $sqlServerName
        serverEndpoint = "${sqlServerName}.database.windows.net"
        subscriptionId = $subscriptionId
    }
}
$source1 = putSource $access_token $sourceSqlPayload

# 7. Create a Scan Configuration
$randomId = -join (((48..57)+(65..90)+(97..122)) * 80 |Get-Random -Count 3 |ForEach-Object{[char]$_})
$scanName = "Scan-${randomId}"
$scanSqlPayload = @{
    kind = "AzureSqlDatabaseCredential"
    name = $scanName
    properties = @{
        databaseName = $sqlDatabaseName
        scanRulesetName = "AzureSqlDatabase"
        scanRulesetType = "System"
        serverEndpoint = "${sqlServerName}.database.windows.net"
        credential = @{
            credentialType = "SqlAuth"
            referenceName = $credentialPayload.name
        }
        collection = @{
            type = "CollectionReference"
            referenceName = $collectionSalesName
        }
    }
}
$scan1 = putScan $access_token $sourceSqlPayload.name $scanSqlPayload

# 8. Trigger Scan
$run1 = runScan $access_token $sourceSqlPayload.name $scanSqlPayload.name

# 9. Load Storage Account with Sample Data
$containerName = "bing"
$storageAccount = Get-AzStorageAccount -ResourceGroupName $resourceGroupName -Name $storageAccountName
$RepoUrl = 'https://api.github.com/repos/microsoft/BingCoronavirusQuerySet/zipball/master'
Invoke-RestMethod -Uri $RepoUrl -OutFile "${containerName}.zip"
if (Test-Path "${containerName}") { Remove-Item "${containerName}" -Recurse -Force }
Expand-Archive -Path "${containerName}.zip"
Set-Location -Path "${containerName}"
Get-ChildItem -File -Recurse | Set-AzStorageBlobContent -Container ${containerName} -Context $storageAccount.Context

# 10. Create a Source (ADLS Gen2)
$sourceAdlsPayload = @{
    id = "datasources/AzureDataLakeStorage"
    kind = "AdlsGen2"
    name = "AzureDataLakeStorage"
    properties = @{
        collection = @{
            referenceName = $collectionMarketingName
            type = 'CollectionReference'
        }
        location = $location
        endpoint = "https://${storageAccountName}.dfs.core.windows.net/"
        resourceGroup = $resourceGroupName
        resourceName = $storageAccountName
        subscriptionId = $subscriptionId
    }
}
$source2 = putSource $access_token $sourceAdlsPayload

# 11. Create a Scan Configuration
$randomId = -join (((48..57)+(65..90)+(97..122)) * 80 |Get-Random -Count 3 |ForEach-Object{[char]$_})
$scanName = "Scan-${randomId}"
$scanAdlsPayload = @{
    kind = "AdlsGen2Msi"
    name = $scanName
    properties = @{
        scanRulesetName = "AdlsGen2"
        scanRulesetType = "System"
        collection = @{
            type = "CollectionReference"
            referenceName = $collectionMarketingName
        }
    }
}
$scan2 = putScan $access_token $sourceAdlsPayload.name $scanAdlsPayload

# 12. Trigger Scan
$run2 = runScan $access_token $sourceAdlsPayload.name $scanAdlsPayload.name

# 13. Run ADF Pipeline
Invoke-AzDataFactoryV2Pipeline -ResourceGroupName $resourceGroupName -DataFactoryName $adfName -PipelineName $adfPipelineName

# 14. Populate Glossary
$glossaryGuid = (createGlossary $access_token).guid
$glossaryTermsTemplateUri = 'https://raw.githubusercontent.com/tayganr/purviewlab/main/assets/import-terms-sample.csv'
importGlossaryTerms $access_token $glossaryGuid $glossaryTermsTemplateUri