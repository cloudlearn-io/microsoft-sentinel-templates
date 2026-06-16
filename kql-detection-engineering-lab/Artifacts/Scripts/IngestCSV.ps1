# Seeds a Log Analytics workspace with sample sign-in telemetry for the
# "Engineer and Tune KQL Detections in Microsoft Sentinel" lab.
#
# Runs as an ARM Microsoft.Resources/deploymentScripts (AzurePowerShell) resource
# during lab provisioning. It pulls a CSV of sign-in events from this public repo
# and POSTs the rows to the workspace via the HTTP Data Collector API, which
# auto-creates the custom table SigninEvents_CL.
#
# Environment variables (set by the deploymentScript):
#   CustomerId - the Log Analytics workspace ID (GUID)
#   SharedKey  - the workspace primary shared key

$CustomerId = ${Env:CustomerId}
$SharedKey  = ${Env:SharedKey}

$DataUrl = "https://raw.githubusercontent.com/cloudlearn-io/microsoft-sentinel-templates/refs/heads/main/kql-detection-engineering-lab/Artifacts/Telemetry/signin_events.csv"
$LogType = "SigninEvents"   # Data Collector API appends _CL -> table SigninEvents_CL

function Build-Signature($customerId, $sharedKey, $date, $contentLength, $method, $contentType, $resource) {
    $xHeaders = "x-ms-date:" + $date
    $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource
    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($sharedKey)
    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.Key = $keyBytes
    $hash = $sha256.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($hash)
    return ('SharedKey {0}:{1}' -f $customerId, $encodedHash)
}

function Post-LogAnalyticsData($customerId, $sharedKey, $body, $logType) {
    $method = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString("r")
    $contentLength = [Text.Encoding]::UTF8.GetByteCount($body)
    $signature = Build-Signature $customerId $sharedKey $rfc1123date $contentLength $method $contentType $resource
    $uri = "https://" + $customerId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"
    $headers = @{
        "Authorization" = $signature
        "Log-Type"      = $logType
        "x-ms-date"     = $rfc1123date
    }
    $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
    Write-Output ("Data Collector API POST status: " + $response.StatusCode)
    return $response.StatusCode
}

Write-Output "Downloading sample sign-in telemetry from $DataUrl"
Invoke-WebRequest -Uri $DataUrl -OutFile "signin_events.csv" -UseBasicParsing
$rows = Import-Csv "signin_events.csv"
Write-Output ("Parsed " + $rows.Count + " sign-in rows; posting to Log-Type $LogType")
$body = ($rows | ConvertTo-Json -Depth 5)
$status = Post-LogAnalyticsData $CustomerId $SharedKey $body $LogType
Write-Output ("Ingest complete (status $status). Table SigninEvents_CL will be queryable within a few minutes.")

$DeploymentScriptOutputs = @{}
$DeploymentScriptOutputs['rowsIngested'] = $rows.Count
$DeploymentScriptOutputs['logType'] = $LogType
