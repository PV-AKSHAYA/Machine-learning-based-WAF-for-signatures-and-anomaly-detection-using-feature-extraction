# PowerShell Script to Test HTTP Classification API and Calculate Metrics
param(
    [string]$ApiUrl = "http://localhost:5001/api/classify"
)

$results = @()

function Test-ClassificationAPI {
    param(
        [hashtable]$RequestData,
        [int]$ActualLabel,
        [int]$RequestNumber
    )
    
    try {
        $jsonBody = $RequestData | ConvertTo-Json -Compress
        $response = Invoke-RestMethod -Uri $ApiUrl -Method POST -ContentType "application/json" -Body $jsonBody -TimeoutSec 30
        
        $prediction = 0
        if ($response.prediction -ne $null) { 
            $prediction = [int]$response.prediction 
        } elseif ($response.is_malicious -ne $null) { 
            $prediction = [int]$response.is_malicious 
        } elseif ($response.result -ne $null) { 
            $prediction = [int]$response.result 
        } elseif ($response.classification -ne $null) { 
            $prediction = [int]$response.classification 
        } elseif ($response -is [int]) {
            $prediction = [int]$response
        } elseif ($response -is [bool]) {
            $prediction = if ($response) { 1 } else { 0 }
        }
        
        $status = if ($prediction -eq $ActualLabel) { "CORRECT" } else { "WRONG" }
        Write-Host "Request $RequestNumber $status - Predicted: $prediction, Actual: $ActualLabel" -ForegroundColor $(if ($prediction -eq $ActualLabel) { "Green" } else { "Red" })
        
        return @{
            Success = $true
            Prediction = $prediction
            Actual = $ActualLabel
            RequestNumber = $RequestNumber
        }
    }
    catch {
        Write-Host "Request $RequestNumber ERROR - $($_.Exception.Message)" -ForegroundColor Yellow
        return @{
            Success = $false
            Prediction = 0
            Actual = $ActualLabel
            RequestNumber = $RequestNumber
        }
    }
}

Write-Host "Starting HTTP Classification API Testing..." -ForegroundColor Cyan
Write-Host "Testing against: $ApiUrl" -ForegroundColor Cyan

if (Test-Path "paste.txt") {
    Write-Host "Loading test data from paste.txt..." -ForegroundColor Yellow
    $csvData = Import-Csv "paste.txt"
    
    $requestNumber = 0
    foreach ($row in $csvData) {
        $requestNumber++
        
        $requestData = @{
            method = $row.method
            url = $row.url
        }
        
        if ($row.payload -and $row.payload -ne "" -and $row.payload -ne "NaN") {
            $requestData.payload = $row.payload
        }
        
        $actualLabel = [int]$row.is_malicious
        $result = Test-ClassificationAPI -RequestData $requestData -ActualLabel $actualLabel -RequestNumber $requestNumber
        $results += $result
        
        if ($requestNumber % 50 -eq 0) {
            Write-Host "Progress: $requestNumber/945 requests completed" -ForegroundColor Blue
        }
    }
} else {
    Write-Host "ERROR: paste.txt file not found!" -ForegroundColor Red
    exit 1
}

# Calculate metrics
$successfulResults = $results | Where-Object { $_.Success -eq $true }
$totalRequests = $successfulResults.Count
$failedRequests = $results.Count - $totalRequests

$predictions = $successfulResults | ForEach-Object { $_.Prediction }
$actualLabels = $successfulResults | ForEach-Object { $_.Actual }

$tp = 0; $tn = 0; $fp = 0; $fn = 0

for ($i = 0; $i -lt $predictions.Count; $i++) {
    $pred = $predictions[$i]
    $actual = $actualLabels[$i]
    
    if ($pred -eq 1 -and $actual -eq 1) { $tp++ }
    elseif ($pred -eq 0 -and $actual -eq 0) { $tn++ }
    elseif ($pred -eq 1 -and $actual -eq 0) { $fp++ }
    elseif ($pred -eq 0 -and $actual -eq 1) { $fn++ }
}

$accuracy = ($tp + $tn) / ($tp + $tn + $fp + $fn)
$precision = if (($tp + $fp) -eq 0) { 0.0 } else { $tp / ($tp + $fp) }
$recall = if (($tp + $fn) -eq 0) { 0.0 } else { $tp / ($tp + $fn) }
$f1Score = if (($precision + $recall) -eq 0) { 0.0 } else { 2 * ($precision * $recall) / ($precision + $recall) }

$balancedAccuracy = if (($tp + $fn) -eq 0 -or ($tn + $fp) -eq 0) { 0.0 } else { (($tp / ($tp + $fn)) + ($tn / ($tn + $fp))) / 2 }

Write-Host "`nModel Accuracy: $([math]::Round($accuracy * 100, 2))%" -ForegroundColor Green
Write-Host "Confusion matrix:" -ForegroundColor White
Write-Host "[[$(($tn).ToString().PadLeft(3)) $(($fp).ToString().PadLeft(3))]" -ForegroundColor White  
Write-Host " [$(($fn).ToString().PadLeft(3)) $(($tp).ToString().PadLeft(3))]]" -ForegroundColor White
Write-Host "`nbalanced_accuracy: $($balancedAccuracy.ToString('F4'))" -ForegroundColor Cyan
Write-Host "f1_score: $($f1Score.ToString('F4'))" -ForegroundColor Cyan
Write-Host "precision: $($precision.ToString('F4'))" -ForegroundColor Cyan
Write-Host "recall: $($recall.ToString('F4'))" -ForegroundColor Cyan

Write-Host "`nTesting completed! Total: $totalRequests, Failed: $failedRequests" -ForegroundColor Green
