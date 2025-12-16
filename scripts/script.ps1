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
# Pragmatic Module Management for Deployment Script Environment
# Azure Deployment Scripts (PowerShell 11.0) come with pre-loaded Az modules
# Work with the existing environment rather than trying to replace modules
# --------------------------------------------------------------------
$ErrorActionPreference = 'Stop'

Write-Host "=== Azure Module Check ===" -ForegroundColor Cyan
Write-Host "Deployment Script: Azure PowerShell 11.0 environment" -ForegroundColor Yellow
Write-Host "Working with pre-loaded Az modules..." -ForegroundColor Yellow

# Show what's already loaded
Write-Host "`nPre-loaded Az modules:" -ForegroundColor Cyan
$loadedModules = Get-Module Az.*
if ($loadedModules) {
    $loadedModules | Format-Table Name, Version -AutoSize
} else {
    Write-Host "  (none - will load as needed)" -ForegroundColor Gray
}

# Check for Az.Purview specifically
$purviewModule = Get-Module Az.Purview -ListAvailable | Select-Object -First 1

if ($purviewModule) {
    Write-Host "`nAz.Purview found: v$($purviewModule.Version)" -ForegroundColor Green
    Write-Host "Attempting to import Az.Purview..." -ForegroundColor Cyan
    
    try {
        Import-Module Az.Purview -Global -ErrorAction Stop
        $loaded = Get-Module Az.Purview
        Write-Host "  ✓ Az.Purview v$($loaded.Version) loaded successfully" -ForegroundColor Green
        $script:UsePurviewRestApi = $false
    } catch {
        Write-Warning "Failed to import Az.Purview: $_"
        Write-Host "Will use REST API fallback for Purview operations" -ForegroundColor Yellow
        $script:UsePurviewRestApi = $true
    }
} else {
    Write-Warning "Az.Purview module not available in this environment"
    Write-Host "Will use REST API for all Purview operations" -ForegroundColor Yellow
    $script:UsePurviewRestApi = $true
}

# Ensure core modules are available
Write-Host "`nVerifying core Az modules..." -ForegroundColor Cyan

$coreModules = @('Az.Accounts', 'Az.Storage', 'Az.DataFactory')
foreach ($moduleName in $coreModules) {
    $module = Get-Module $moduleName
    if (-not $module) {
        Write-Host "  Loading $moduleName..." -ForegroundColor Yellow
        try {
            Import-Module $moduleName -Global -ErrorAction Stop
            $module = Get-Module $moduleName
            Write-Host "  ✓ $moduleName v$($module.Version)" -ForegroundColor Green
        } catch {
            Write-Error "Failed to load $moduleName : $_"
            throw
        }
    } else {
        Write-Host "  ✓ $moduleName v$($module.Version) already loaded" -ForegroundColor Green
    }
}

Write-Host "`n=== Module Check Complete ===" -ForegroundColor Green
Write-Host "Loaded Az modules:" -ForegroundColor Cyan
Get-Module Az.* | Format-Table Name, Version -AutoSize

if ($script:UsePurviewRestApi) {
    Write-Host "`n⚠️  NOTE: Using REST API for Purview operations" -ForegroundColor Yellow
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

# Add UAMI to Root Collection Admin using REST API
# This is more reliable than Az.Purview cmdlets in deployment script environments
Write-Host "Adding managed identity to Purview root collection..." -ForegroundColor Yellow
Write-Host "Using Azure Management REST API..." -ForegroundColor Cyan

try {
    # Get Azure management API token
    Write-Host "  Getting access token..." -ForegroundColor Gray
    $token = (Get-AzAccessToken -ResourceUrl "https://management.azure.com/").Token
    
    # Build the REST API URL
    $apiUrl = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.Purview/accounts/$accountName/addRootCollectionAdmin?api-version=2021-07-01"
    
    Write-Host "  Adding objectId $objectId to root collection..." -ForegroundColor Gray
    
    # Prepare request body
    $body = @{
        objectId = $objectId
    } | ConvertTo-Json
    
    # Make the REST API call
    $response = Invoke-RestMethod -Uri $apiUrl `
        -Method Post `
        -Headers @{
            'Authorization' = "Bearer $token"
            'Content-Type' = 'application/json'
        } `
        -Body $body `
        -ErrorAction Stop
    
    Write-Host "  ✓ Successfully added managed identity to root collection" -ForegroundColor Green
    
} catch {
    $errorMessage = $_.Exception.Message
    $errorResponse = $_.Exception.Response
    
    Write-Error "Failed to add managed identity to root collection: $errorMessage"
    
    if ($errorResponse) {
        Write-Host "  Status Code: $($errorResponse.StatusCode)" -ForegroundColor Red
        Write-Host "  Status Description: $($errorResponse.StatusDescription)" -ForegroundColor Red
    }
    
    # Check if it's an "already exists" error (which is OK)
    if ($errorMessage -like "*already exists*" -or $errorMessage -like "*already a member*") {
        Write-Host "  ℹ️  Identity is already a member of root collection - continuing..." -ForegroundColor Yellow
    } else {
        throw
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