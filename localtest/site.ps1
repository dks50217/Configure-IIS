function Create-New-Site
{
  param(
    [string]$siteName, 
    [string]$siteFolder,
    [string]$appPool,
    [string]$autoStart,
    [string]$preload
  )

  $isSuccess = $false
  $isSiteExist = $false
  $isFolderExist = $false
  $isAutoStart = $false
  $isPreLoad = $false
  $isAppPoolExist = $false
  $reason = "";

  try
  {
    Import-Module WebAdministration;
    
    $isAppPoolExist = Test-Path "IIS:\AppPools\$appPool";
    $isSiteExist = Test-Path "IIS:\AppPools\$siteName";
    $isFolderExist = Test-Path $siteFolder;
    $isPre

    if ($isAppPoolExist -eq $false)
    {
       $reason = $reason + "appPool: [$appPool] is not exist,"
    }

    if ($isSiteExist -eq $true)
    {
       $reason = $reason + "site: [$siteName] is exist,"
    }

    if ($isFolderExist -eq $false)
    {
      $reason = $reason + "siteFolder: [$siteFolder] is not exist,"
    }

    if ($autoStart -eq "1" ) {$isAutoStart = $true};
    if ($preload -eq "1" ) {$isPreLoad = $true};

    $readyCreate = ($isSiteExist -eq $false) -and ($isFolderExist -eq $true) -and ($isAppPoolExist -eq $true)

    if ($readyCreate)
    {
      $result = New-Website -Name $siteName -ApplicationPool $appPool -PhysicalPath $siteFolder
      Set-ItemProperty "IIS:\Sites\$siteName" serverAutoStart $isAutoStart
      Set-ItemProperty "IIS:\Sites\$siteName" applicationDefaults.preloadEnabled $isPreLoad
      $isSuccess = $true;
    }
    else
    {
      $reason = "create site: [$siteName] fail," + $reason;
    }
  }
  catch
  {
    Write-Host "An error occurred:"
    Write-Host $reason = $_
  }

  New-Object -TypeName PSCustomObject -Property @{result=$result;isSuccess=$isSuccess;reason=$reason}
}

function Set-Site
{
  param(
    [string]$siteName, 
    [string]$siteFolder,
    [string]$appPool,
    [string]$autoStart,
    [string]$preload
  )

  $isSuccess = $false
  $isSiteExist = $false
  $isFolderExist = $false
  $isAutoStart = $false
  $isPreLoad = $false
  $isAppPoolExist = $false
  $reason = "";

  try
  {
     Import-Module WebAdministration

     $isAppPoolExist = Test-Path "IIS:\AppPools\$appPool";
     $isSiteExist = Test-Path "IIS:\Sites\$siteName";
     $isFolderExist = Test-Path $siteFolder;

    if ($isAppPoolExist -eq $false)
    {
       $reason = $reason + "appPool: [$appPool] is not exist,"
    }

    if ($isSiteExist -eq $false)
    {
       $reason = $reason + "site: [$siteName] is not exist,"
    }

    if ($isFolderExist -eq $false)
    {
      $reason = $reason + "siteFolder: [$siteFolder] is not exist,"
    }

    if ($autoStart -eq "1" ) {$isAutoStart = $true};
    if ($preload -eq "1" ) {$isPreLoad = $true};

    $readySet = ($isSiteExist -eq $true) -and ($isFolderExist -eq $true) -and ($isAppPoolExist -eq $true)
    
    if ($readySet)
    {
      Set-ItemProperty "IIS:\Sites\$siteName" ApplicationPool $appPool
      Set-ItemProperty "IIS:\Sites\$siteName" PhysicalPath $siteFolder
      Set-ItemProperty "IIS:\Sites\$siteName" serverAutoStart $isAutoStart
      Set-ItemProperty "IIS:\Sites\$siteName" applicationDefaults.preloadEnabled $isPreLoad
      $isSuccess = $true;
    }
    else
    {
      $reason = "set site: [$siteName] fail," + $reason;
    }
  }
  catch
  {
    Write-Host "An error occurred:"
    $reason = $_
  }

  New-Object -TypeName PSCustomObject -Property @{result=$result;isSuccess=$isSuccess;reason=$reason}
}

function Remove-Site
{
  param(
    [string]$siteName
  )

  $isSuccess = $false
  $isSiteExist = $false
  $existAppCount = 0
  $reason = "";

  try
  {
    Import-Module WebAdministration

    #Check Site Exists
    $isSiteExist = Test-Path "IIS:\Sites\$siteName"

    if ($isSiteExist -eq $false)
    {
      $reason = $reason + "site: [$siteName] not exists,"
    }

    if ($isSiteExist)
    {
        #Check Application Exists
        $existAppCount = (Get-ChildItem "IIS:\Sites\$siteName").count;
    }

    if ($existAppCount -gt 1)
    {
       $reason = $reason + "can't remove site: [$siteName], because app exists, count : [$existAppCount],"
    }

    $readyRemove = ($isSiteExist -eq $true) -and ($existAppCount -eq 1)

    if ($readyRemove)
    {
      $result = Remove-WebSite -Name $siteName
      $isSuccess = $true
    }
    else
    {
      $reason = "can't remove site: [$siteName]," + $reason;
    }
  }
  catch
  {
    Write-Host "An error occurred:"
    $reason = $_
  }

  New-Object -TypeName PSCustomObject -Property @{result=$result;isSuccess=$isSuccess;reason=$reason}
}

function Set-WebBinding
{
  param(
    [string]$siteName,
    [string]$bindingJsonList
  )

  $isSuccess = $false;
  $reason = "";
  $result = New-Object -TypeName 'System.Collections.ArrayList';

  try
  {
    #Convert To PSObject
    $bindingList = $bindingJsonList | ConvertFrom-Json
     
    #Remove all
    $orgBindingList = Get-WebBinding $siteName |Select-Object -ExpandProperty bindingInformation

    foreach ($item in $orgBindingList)
    {
      $orgIP = $item.split(':')[0];
      Get-WebBinding -Port $orgIP -Name $siteName | Remove-WebBinding;
    }
    
    #Create all  
    foreach ($item in $bindingList)
    {
      $bindObject = [PSCustomObject]@{
        ip =$item.ip
        port = $item.port
        header = $item.header
      };
      New-WebBinding -Name $siteName -IPAddress $item.ip -Port $item.port -HostHeader $item.header  
      $result.Add($bindObject);
    }

    $isSuccess = $true;
  }
  catch
  {
    Write-Host "An error occurred:"
    Write-Host $reason = $_
  }

  New-Object -TypeName PSCustomObject -Property @{result=$result;isSuccess=$isSuccess;reason=$reason}
}

#Create-New-Site "michaelSite" "D:\Demo_Web\cardSample" "michaelPool" "1" "1"

#Set-Site "michaelSite" "D:\Demo_Web\Chartjs" "michaelPool" "1" "1"

#Remove-Site "michaelSite"

#$bindingListJson = "[{'ip':'*','port':'9487',header:'test.com'},{'ip':'*','port':'80',header:''}]";
#Set-WebBinding "Default Web Site" $bindingListJson
