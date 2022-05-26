function Get-MyCommands 
{
    Get-Content -Path "./Remote-IIS.ps1" | Select-String -Pattern "^function.+" | ForEach-Object {
        [Regex]::Matches($_, "^function ([a-z.-]+)","IgnoreCase").Groups[1].Value
    } | Where-Object { $_ -ine "prompt" } | Sort-Object
}

Get-MyCommands