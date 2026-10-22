@{
    # Errors and warnings fail CI. The collector must keep running on Windows PowerShell 5.1,
    # the version shipped with every supported Windows Server.
    Severity     = @('Error', 'Warning')
    IncludeRules = @('*')
    Rules        = @{
        PSUseCompatibleSyntax = @{
            Enable         = $true
            TargetVersions = @('5.1', '7.4')
        }
    }
}
