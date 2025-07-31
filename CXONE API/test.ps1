

*****************************************************apiTokenLogin.ps1*****************************************************
param(
    [System.Uri]$cx1TokenURL,
    [System.Uri]$cx1URL,
    [System.Uri]$cx1IamURL,
    [string]$cx1Tenant,
    [string]$PAT,
    [string]$dgb,
)

. "rest_util.ps1"
$session = @{}

    Write-Debug "Executing new login"

$query_elems = @{
    "grant_type" = "refresh_token";
    "client_id" = "ast-app";
    "refresh_token" = $PAT;
}

$api_path = "$cx1Tenant/protocol/openid-connect/token"

$api_uri_base = New-Object System.Uri $cx1TokenURL, $api_path
$api_uri = New-Object System.UriBuilder $api_uri_base

$query = GetQueryStringFromHashtable $query_elems

$session.reauth_uri = $api_uri.Uri;
$session.reauth_body = $query;
$session.base_url = $cx1URL;
$session.auth_url = $cx1IamURL;
$session.tenant = $cx1Tenant;

$resp = Invoke-RestMethod -Method Post -Uri $session.reauth_uri -ContentType "application/x-www-form-urlencoded" -Body $session.reauth_body

$session.auth_header - [String]::format("{0} {1}", $resp.token_type, $resp.access_token);
$session.expires_at = $(Get-Date).AddSeconds($resp.expires_in);

return $session;

*****************************************************apiTokenLogin.ps1*****************************************************


*****************************************************Checkmarx.ps1*****************************************************
Add-Type -AssemblyName System.Web

[System.Uri]$cx1TokenURL = "cxone-preprod/auth/realms/"
[System.Uri]$cx1URL = "cxone-preprod"
[System.Uri]$cx1IamURL = "cxone-preprod/auth/api/rest/"
[string]$cx1Tenant = "cxone-preprod"

. "rest_util.ps1"

$session = @{}

    Write-Debug "Executing new login"

$query_elems = @{
    "grant_type" = "refresh_token";
    "client_id" = "ast-app";
    "refresh_token" = $PAT;
}

$api_path = "$cx1Tenant/protocol/openid-connect/token"

$api_uri_base = New-Object System.Uri $cx1TokenURL, $api_path
$api_uri = New-Object System.UriBuilder $api_uri_base

$query = GetQueryStringFromHashtable $query_elems

$session.reauth_uri = $api_uri.Uri;
$session.reauth_body = $query;
$session.base_url = $cx1URL;
$session.auth_url = $cx1IamURL;
$session.tenant = $cx1Tenant;

$resp = Invoke-RestMethod -Method Post -Uri $session.reauth_uri -ContentType "application/x-www-form-urlencoded" -Body $session.reauth_body

$session.auth_header - [String]::format("{0} {1}", $resp.token_type, $resp.access_token);
$session.expires_at = $(Get-Date).AddSeconds($resp.expires_in);

$scriptPath = "PSScriptRoot\scriptB.ps1"
$apikey = "apikey"
$base_url = "cxone-preprod/api/"
$limit = "limit=1000"
$bearer = "Bearer $apikey"
$request = Invoke-WebRequest -Uri "cxone-preprod/api/projects/?offset=0&limit=1000" -Headers @{'Accept' = 'application/json';'Authorization' = $bearer}
$projects = $request.Content | ConvertFrom-Json

foreach ($project in $projects.projects) {
$request = Invoke-WebRequest ('cxone-preprod/api/projects/last-scan?offset=0&limit=20&project-ids=' + $project.id) - Headers @{'Accept' = 'application/json';'Authorization' = ('Bearer ' + $resp.access_token)}
$project.name
$data = $request.Content | ConvertFrom-Json
$data.($request.Content.substring(2,36)).updatedAt
}

#grab latest scan from project
$lastscancall = 'projects/last-scan?offset=0&limit=20&project-ids='
$response = Invoke-WebRequest ($baseurl + $lastscancall + $project.id) -Headers @{'Accept' = 'application/json';'Authorization' = $bearer}

#grab scan results
$scanresults = 'sast-results/?scan-id='
$response = Invoke-WebRequest ($baseurl + $lastscancall + $scanid) -Headers @{'Accept' = 'application/json';'Authorization' = $bearer}

function Escape-String {
    param(
        [string]$input
    )
    $string -replace '([`"$\^&|<>()#@%;,\s\t\n\r\f{}])', '`$1'
}

function logintoken{

    param(
        [System.Uri]$cx1TokenURL,
        [System.Uri]$cx1URL,
        [System.Uri]$cx1IamURL,
        [string]$cx1Tenant,
        [string]$PAT,
        [string]$dgb
    )

    Add-Type -AssemblyName System.Web
    . "rest_util.ps1"

    $session = @{}

        Write-Debug "Executing new login"

    $query_elems = @{
        "grant_type" = "refresh_token";
        "client_id" = "ast-app";
        "refresh_token" = $PAT;
    }

    $api_path = "$cx1Tenant/protocol/openid-connect/token"

    $api_uri_base = New-Object System.Uri $cx1TokenURL, $api_path
    $api_uri = New-Object System.UriBuilder $api_uri_base

    $query = GetQueryStringFromHashtable $query_elems

    $session.reauth_uri = $api_uri.Uri;
    $session.reauth_body = $query;
    $session.base_url = $cx1URL;
    $session.auth_url = $cx1IamURL;
    $session.tenant = $cx1Tenant;

    $resp = Invoke-RestMethod -Method Post -Uri $session.reauth_uri -ContentType "application/x-www-form-urlencoded" -Body $session.reauth_body
    
    $session.auth_header = [String]::format("{0} {1}", $resp.token_type, $resp.access_token);
    $session.expires_at = $(Get-Date).AddSeconds($resp.expires_in);

    return $session;

}

$session = logintoken('cxone-preprod/auth/realms/', 'cxone-preprod', 'cxone-preprod/auth/api/rest/', 'cxone-preprod', $PAT, $dgb)


*****************************************************Checkmarx.ps1*****************************************************



*****************************************************rest_util.ps1*****************************************************

function GetAuthHeaders ($session_token) {
    @{
        Authorization = $session_token.auth_header;
    }
}

function GetRestHeadersForRequest($session_token, $accept_type) {
    GetAuthHeaders $session_token + @{
        'Accept' = $accept_type;
    }
}

function GetRestHeadersForJSONRequest($session_token) {
    GetRestHeadersForRequest $session_token 'application/json';
}

function GetQueryStringFromHashtable($table) {
    $query_builder = New-Object System.Text.StringBuilder
    $sep = ""

    $table.Keys | % {
        [void]$query_builder.Append($sep).AppendFormat("{0}={1}", $_, [System.Web.HttpUtility]::UrlEncode($table[$_]))
        $sep = "&"
    }

    $query_builder.ToString()
}

*****************************************************rest_util.ps1*****************************************************
