# AzurePowerCommands - Microsoft Graph edition
# Public commands use the Microsoft Graph PowerShell Get-Mg naming convention.
# Recommended delegated scopes:
#   Directory.Read.All
#   AuditLog.Read.All
#   UserAuthenticationMethod.Read.All
#   Policy.Read.All
# Some operations also require an appropriate Microsoft Entra directory role.

Update-TypeData -TypeName 'AzurePowerCommands.User' -DefaultDisplayPropertySet @('ObjectType', 'ObjectId', 'DisplayName', 'UserPrincipalName', 'AccountEnabled') -Force
Update-TypeData -TypeName 'AzurePowerCommands.Group' -DefaultDisplayPropertySet @('ObjectType', 'ObjectId', 'DisplayName', 'Mail', 'SecurityEnabled', 'IsAssignableToRole') -Force
Update-TypeData -TypeName 'AzurePowerCommands.ServicePrincipal' -DefaultDisplayPropertySet @('ObjectType', 'ObjectId', 'DisplayName', 'AppId', 'AccountEnabled') -Force
Update-TypeData -TypeName 'AzurePowerCommands.Application' -DefaultDisplayPropertySet @('ObjectType', 'ObjectId', 'DisplayName', 'AppId') -Force
Update-TypeData -TypeName 'AzurePowerCommands.DirectoryObject' -DefaultDisplayPropertySet @('ObjectType', 'ObjectId', 'DisplayName') -Force

$script:AzurePowerDirectoryObjectCache = @{}
$script:AzurePowerDirectoryObjectCacheTenantId = $null

function Assert-AzurePowerGraphConnection {
    [CmdletBinding()]
    param()

    if (-not (Get-Command Get-MgContext -ErrorAction SilentlyContinue)) {
        throw 'Microsoft Graph PowerShell is not installed or imported.'
    }

    $Context = Get-MgContext
    if (-not $Context) {
        throw "You're not connected with Microsoft Graph. Connect with Connect-MgGraph."
    }

    if ($script:AzurePowerDirectoryObjectCacheTenantId -ne $Context.TenantId) {
        $script:AzurePowerDirectoryObjectCache = @{}
        $script:AzurePowerDirectoryObjectCacheTenantId = $Context.TenantId
    }
}

function Get-AzurePowerPropertyValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $InputObject,

        [Parameter(Mandatory = $true)]
        [string[]]$Name
    )

    foreach ($PropertyName in $Name) {
        if ($null -ne $InputObject.PSObject.Methods['ContainsKey']) {
            if ($InputObject.ContainsKey($PropertyName)) {
                return $InputObject[$PropertyName]
            }
        }
        elseif ($InputObject -is [System.Collections.IDictionary]) {
            $Dictionary = [System.Collections.IDictionary]$InputObject
            if ($Dictionary.Contains([object]$PropertyName)) {
                return $Dictionary[$PropertyName]
            }
        }

        $Property = $InputObject.PSObject.Properties[$PropertyName]
        if ($null -ne $Property) {
            return $Property.Value
        }

        $AdditionalPropertiesProperty = $InputObject.PSObject.Properties['AdditionalProperties']
        if ($null -ne $AdditionalPropertiesProperty) {
            $AdditionalProperties = $AdditionalPropertiesProperty.Value

            if ($null -ne $AdditionalProperties -and $null -ne $AdditionalProperties.PSObject.Methods['ContainsKey']) {
                if ($AdditionalProperties.ContainsKey($PropertyName)) {
                    return $AdditionalProperties[$PropertyName]
                }
            }
            elseif ($AdditionalProperties -is [System.Collections.IDictionary]) {
                $Dictionary = [System.Collections.IDictionary]$AdditionalProperties
                if ($Dictionary.Contains([object]$PropertyName)) {
                    return $Dictionary[$PropertyName]
                }
            }
        }
    }

    return $null
}

function Get-AzurePowerObjectId {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $InputObject
    )

    if ($InputObject -is [string]) {
        return [string]$InputObject
    }

    $Id = Get-AzurePowerPropertyValue -InputObject $InputObject -Name @('Id', 'ObjectId', 'id', 'objectId')
    if ([string]::IsNullOrWhiteSpace([string]$Id)) {
        throw 'The supplied object does not contain an Id or ObjectId property.'
    }

    return [string]$Id
}

function Get-AzurePowerObjectType {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $InputObject
    )

    $ObjectType = Get-AzurePowerPropertyValue -InputObject $InputObject -Name @('ObjectType', 'objectType')
    if ($ObjectType) {
        switch -Regex ([string]$ObjectType) {
            '^user$'             { return 'User' }
            '^group$'            { return 'Group' }
            '^serviceprincipal$' { return 'ServicePrincipal' }
            '^application$'      { return 'Application' }
        }
    }

    $ODataType = Get-AzurePowerPropertyValue -InputObject $InputObject -Name @('@odata.type', 'ODataType')
    if ($ODataType) {
        switch -Regex ([string]$ODataType) {
            'microsoft\.graph\.user$'             { return 'User' }
            'microsoft\.graph\.group$'            { return 'Group' }
            'microsoft\.graph\.servicePrincipal$' { return 'ServicePrincipal' }
            'microsoft\.graph\.application$'      { return 'Application' }
        }
    }

    foreach ($TypeName in $InputObject.PSObject.TypeNames) {
        switch -Regex ($TypeName) {
            'MicrosoftGraphUser$'             { return 'User' }
            'MicrosoftGraphGroup$'            { return 'Group' }
            'MicrosoftGraphServicePrincipal$' { return 'ServicePrincipal' }
            'MicrosoftGraphApplication$'      { return 'Application' }
            'AzurePowerCommands\.User$'             { return 'User' }
            'AzurePowerCommands\.Group$'            { return 'Group' }
            'AzurePowerCommands\.ServicePrincipal$' { return 'ServicePrincipal' }
            'AzurePowerCommands\.Application$'      { return 'Application' }
        }
    }

    if (Get-AzurePowerPropertyValue -InputObject $InputObject -Name @('UserPrincipalName', 'userPrincipalName')) {
        return 'User'
    }

    if (Get-AzurePowerPropertyValue -InputObject $InputObject -Name @('AppId', 'appId')) {
        return 'ServicePrincipal'
    }

    if ($null -ne (Get-AzurePowerPropertyValue -InputObject $InputObject -Name @('SecurityEnabled', 'securityEnabled'))) {
        return 'Group'
    }

    return 'DirectoryObject'
}

function ConvertTo-AzurePowerDirectoryObject {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        $InputObject,

        [Parameter(Mandatory = $false)]
        [ValidateSet('User', 'Group', 'ServicePrincipal', 'Application', 'DirectoryObject')]
        [string]$ObjectType
    )

    process {
        $ResolvedObjectType = $ObjectType
        if (-not $ResolvedObjectType) {
            $ResolvedObjectType = Get-AzurePowerObjectType -InputObject $InputObject
        }

        $Id = Get-AzurePowerObjectId -InputObject $InputObject
        $ODataType = Get-AzurePowerPropertyValue -InputObject $InputObject -Name @('@odata.type', 'ODataType')

        [PSCustomObject]@{
            PSTypeName           = "AzurePowerCommands.$ResolvedObjectType"
            ObjectType           = $ResolvedObjectType
            ObjectId             = $Id
            Id                   = $Id
            DisplayName          = Get-AzurePowerPropertyValue -InputObject $InputObject -Name @('DisplayName', 'displayName')
            UserPrincipalName    = Get-AzurePowerPropertyValue -InputObject $InputObject -Name @('UserPrincipalName', 'userPrincipalName')
            AppId                = Get-AzurePowerPropertyValue -InputObject $InputObject -Name @('AppId', 'appId')
            AccountEnabled       = Get-AzurePowerPropertyValue -InputObject $InputObject -Name @('AccountEnabled', 'accountEnabled')
            Mail                 = Get-AzurePowerPropertyValue -InputObject $InputObject -Name @('Mail', 'mail')
            SecurityEnabled      = Get-AzurePowerPropertyValue -InputObject $InputObject -Name @('SecurityEnabled', 'securityEnabled')
            IsAssignableToRole   = Get-AzurePowerPropertyValue -InputObject $InputObject -Name @('IsAssignableToRole', 'isAssignableToRole')
            ServicePrincipalType = Get-AzurePowerPropertyValue -InputObject $InputObject -Name @('ServicePrincipalType', 'servicePrincipalType')
            ODataType            = $ODataType
        }
    }
}

function Resolve-AzurePowerDirectoryObject {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        $DirectoryObject
    )

    process {
        $Id = Get-AzurePowerObjectId -InputObject $DirectoryObject
        $ObjectType = Get-AzurePowerObjectType -InputObject $DirectoryObject
        $CacheKey = "$ObjectType|$Id"

        if ($script:AzurePowerDirectoryObjectCache.ContainsKey($CacheKey)) {
            $script:AzurePowerDirectoryObjectCache[$CacheKey]
            return
        }

        $ResolvedObject = $null

        try {
            switch ($ObjectType) {
                'User' {
                    $ResolvedObject = Get-MgUser -UserId $Id -Property @('Id', 'DisplayName', 'UserPrincipalName', 'AccountEnabled', 'Mail') -ErrorAction Stop |
                        ConvertTo-AzurePowerDirectoryObject -ObjectType User
                }
                'Group' {
                    $ResolvedObject = Get-MgGroup -GroupId $Id -Property @('Id', 'DisplayName', 'Mail', 'SecurityEnabled', 'IsAssignableToRole') -ErrorAction Stop |
                        ConvertTo-AzurePowerDirectoryObject -ObjectType Group
                }
                'ServicePrincipal' {
                    $ResolvedObject = Get-MgServicePrincipal -ServicePrincipalId $Id -Property @('Id', 'DisplayName', 'AppId', 'AccountEnabled', 'ServicePrincipalType') -ErrorAction Stop |
                        ConvertTo-AzurePowerDirectoryObject -ObjectType ServicePrincipal
                }
                'Application' {
                    $ResolvedObject = Get-MgApplication -ApplicationId $Id -Property @('Id', 'DisplayName', 'AppId') -ErrorAction Stop |
                        ConvertTo-AzurePowerDirectoryObject -ObjectType Application
                }
                default {
                    $ResolvedObject = ConvertTo-AzurePowerDirectoryObject -InputObject $DirectoryObject -ObjectType DirectoryObject
                }
            }
        }
        catch {
            Write-Verbose "Could not resolve $ObjectType object ${Id}: $($_.Exception.Message)"
            $ResolvedObject = ConvertTo-AzurePowerDirectoryObject -InputObject $DirectoryObject -ObjectType $ObjectType
        }

        $script:AzurePowerDirectoryObjectCache[$CacheKey] = $ResolvedObject
        $ResolvedObject
    }
}

function Invoke-AzurePowerGraphCollectionRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri
    )

    $NextLink = $Uri
    while ($NextLink) {
        $Response = Invoke-MgGraphRequest -Method GET -Uri $NextLink -ErrorAction Stop
        $Values = Get-AzurePowerPropertyValue -InputObject $Response -Name @('value')

        if ($null -ne $Values) {
            foreach ($Value in @($Values)) {
                $Value
            }
        }

        $NextLink = Get-AzurePowerPropertyValue -InputObject $Response -Name @('@odata.nextLink')
    }
}

function Get-AzurePowerGroupDirectMembers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupId,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeServicePrincipals
    )

    if ($IncludeServicePrincipals) {
        # The v1.0 group members endpoint has a documented limitation where service
        # principals can be omitted. Beta is used only for this compatibility path.
        $EscapedGroupId = [uri]::EscapeDataString($GroupId)
        $Members = Invoke-AzurePowerGraphCollectionRequest -Uri "https://graph.microsoft.com/beta/groups/$EscapedGroupId/members"
    }
    else {
        $Members = Get-MgGroupMember -GroupId $GroupId -All -ErrorAction Stop
    }

    foreach ($Member in @($Members)) {
        Resolve-AzurePowerDirectoryObject -DirectoryObject $Member
    }
}

function Get-AzurePowerGroupMembersRecursive {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupId,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Users', 'Groups', 'ServicePrincipals')]
        [string]$Mode,

        [Parameter(Mandatory = $true)]
        [hashtable]$VisitedGroups
    )

    if ($VisitedGroups.ContainsKey($GroupId)) {
        return
    }
    $VisitedGroups[$GroupId] = $true

    $Members = @(Get-AzurePowerGroupDirectMembers -GroupId $GroupId -IncludeServicePrincipals:($Mode -eq 'ServicePrincipals'))
    $GroupMembers = @($Members | Where-Object { $_.ObjectType -eq 'Group' })

    switch ($Mode) {
        'Users' {
            $Members | Where-Object { $_.ObjectType -eq 'User' }
        }
        'Groups' {
            $GroupMembers
        }
        'ServicePrincipals' {
            $Members | Where-Object { $_.ObjectType -eq 'ServicePrincipal' }
        }
    }

    foreach ($GroupMember in $GroupMembers) {
        Get-AzurePowerGroupMembersRecursive -GroupId $GroupMember.ObjectId -Mode $Mode -VisitedGroups $VisitedGroups
    }
}

function Get-AzurePowerDirectoryRoleDirectMembers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DirectoryRoleId
    )

    $Members = Get-MgDirectoryRoleMember -DirectoryRoleId $DirectoryRoleId -All -ErrorAction Stop
    foreach ($Member in @($Members)) {
        Resolve-AzurePowerDirectoryObject -DirectoryObject $Member
    }
}

function Get-AzurePowerDirectoryRoleMembersRecursive {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DirectoryRoleId,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Users', 'Groups', 'ServicePrincipals')]
        [string]$Mode
    )

    $Members = @(Get-AzurePowerDirectoryRoleDirectMembers -DirectoryRoleId $DirectoryRoleId)
    $GroupMembers = @($Members | Where-Object { $_.ObjectType -eq 'Group' })

    switch ($Mode) {
        'Users' {
            $Members | Where-Object { $_.ObjectType -eq 'User' }
        }
        'Groups' {
            $GroupMembers
        }
        'ServicePrincipals' {
            $Members | Where-Object { $_.ObjectType -eq 'ServicePrincipal' }
        }
    }

    $VisitedGroups = @{}
    foreach ($GroupMember in $GroupMembers) {
        Get-AzurePowerGroupMembersRecursive -GroupId $GroupMember.ObjectId -Mode $Mode -VisitedGroups $VisitedGroups
    }
}

function Get-AzurePowerGroupOwners {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupId
    )

    # Beta is used because v1.0 can omit service principals that own groups.
    $EscapedGroupId = [uri]::EscapeDataString($GroupId)
    $Owners = Invoke-AzurePowerGraphCollectionRequest -Uri "https://graph.microsoft.com/beta/groups/$EscapedGroupId/owners"
    foreach ($Owner in @($Owners)) {
        Resolve-AzurePowerDirectoryObject -DirectoryObject $Owner
    }
}

function Get-AzurePowerServicePrincipalOwners {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServicePrincipalId
    )

    $Owners = Get-MgServicePrincipalOwner -ServicePrincipalId $ServicePrincipalId -All -ErrorAction Stop
    foreach ($Owner in @($Owners)) {
        Resolve-AzurePowerDirectoryObject -DirectoryObject $Owner
    }
}

function Get-AzurePowerOwnerLabel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        $Owner
    )

    process {
        if ($Owner.ObjectType -eq 'User' -and $Owner.UserPrincipalName) {
            $Owner.UserPrincipalName
        }
        elseif ($Owner.DisplayName) {
            $Owner.DisplayName
        }
        elseif ($Owner.AppId) {
            $Owner.AppId
        }
        else {
            $Owner.ObjectId
        }
    }
}

function Get-AzurePowerPrivilegedRoleNames {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$OverviewSubset
    )

    if ($OverviewSubset) {
        return @(
            'Global administrator',
            'Application administrator',
            'Authentication Administrator',
            'Billing administrator',
            'Cloud application administrator',
            'Conditional Access administrator',
            'Exchange administrator',
            'Helpdesk administrator',
            'Password administrator',
            'Privileged authentication administrator',
            'Privileged Role Administrator',
            'Security administrator',
            'SharePoint administrator',
            'User administrator'
        )
    }

    return @(
        'Global administrator',
        'Application administrator',
        'Authentication Administrator',
        'Billing administrator',
        'Cloud application administrator',
        'Conditional Access administrator',
        'Exchange administrator',
        'Helpdesk administrator',
        'Password administrator',
        'Privileged authentication administrator',
        'Privileged Role Administrator',
        'Security administrator',
        'SharePoint administrator',
        'User administrator',
        'Authentication policy administrator',
        'Directory writers',
        'External identity provider administrator',
        'Hybrid identity administrator',
        'Identity governance administrator',
        'Intune Administrator',
        'License administrator',
        'Partner tier 1 support',
        'Partner tier 2 support',
        'Dynamics 365 Administrator',
        'Dynamics 365 Business Central Administrator',
        'Power Platform Administrator'
    )
}

function Get-MgGroupMemberRecursive {
<#
.SYNOPSIS
Author: Jony Schats - 0xjs
Required Dependencies: Get-MgGroupMember, Invoke-MgGraphRequest
Optional Dependencies: None

.DESCRIPTION
Recursively search through Microsoft Entra groups and only return unique user objects. Requires a group from Get-MgGroup as input.

.PARAMETER Group
A group object returned by Get-MgGroup, or another object containing an Id or ObjectId property.

.PARAMETER ReturnGroups
Return group objects instead of user objects.

.PARAMETER ReturnServicePrincipals
Return service principals instead of user objects.

.EXAMPLE
Get-MgGroup -GroupId <ID> | Get-MgGroupMemberRecursive

.EXAMPLE
Get-MgGroup -All | Where-Object -Property DisplayName -eq "<GROUP>" | Get-MgGroupMemberRecursive
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        $Group,

        [Parameter(Mandatory = $false)]
        [switch]$ReturnGroups,

        [Parameter(Mandatory = $false)]
        [switch]$ReturnServicePrincipals
    )

    begin {
        Assert-AzurePowerGraphConnection
        $Output = @()
        $VisitedGroups = @{}
    }

    process {
        $GroupId = Get-AzurePowerObjectId -InputObject $Group
        $DisplayName = Get-AzurePowerPropertyValue -InputObject $Group -Name @('DisplayName', 'displayName')
        Write-Verbose "Enumerating $DisplayName"

        if ($ReturnGroups) {
            $Mode = 'Groups'
        }
        elseif ($ReturnServicePrincipals) {
            $Mode = 'ServicePrincipals'
        }
        else {
            $Mode = 'Users'
        }

        $Output += Get-AzurePowerGroupMembersRecursive -GroupId $GroupId -Mode $Mode -VisitedGroups $VisitedGroups
    }

    end {
        $Output | Where-Object { $_ } | Sort-Object -Property ObjectId -Unique
    }
}

function Get-MgDirectoryRoleMemberRecursive {
<#
.SYNOPSIS
Author: Jony Schats - 0xjs
Required Dependencies: Get-MgDirectoryRoleMember, Get-MgGroupMemberRecursive
Optional Dependencies: None

.DESCRIPTION
Recursively search through Microsoft Entra directory roles and only return unique user objects. Requires a role from Get-MgDirectoryRole as input.

.PARAMETER RoleGroup
A directory role object returned by Get-MgDirectoryRole, or another object containing an Id or ObjectId property.

.PARAMETER ReturnGroups
Return group objects instead of user objects.

.PARAMETER ReturnServicePrincipals
Return service principals instead of user objects.

.EXAMPLE
Get-MgDirectoryRole -DirectoryRoleId <ID> | Get-MgDirectoryRoleMemberRecursive

.EXAMPLE
Get-MgDirectoryRole -All | Where-Object -Property DisplayName -eq "<ROLE>" | Get-MgDirectoryRoleMemberRecursive
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        $RoleGroup,

        [Parameter(Mandatory = $false)]
        [switch]$ReturnGroups,

        [Parameter(Mandatory = $false)]
        [switch]$ReturnServicePrincipals
    )

    begin {
        Assert-AzurePowerGraphConnection
        $Output = @()
    }

    process {
        $RoleId = Get-AzurePowerObjectId -InputObject $RoleGroup
        $DisplayName = Get-AzurePowerPropertyValue -InputObject $RoleGroup -Name @('DisplayName', 'displayName')
        Write-Verbose "Enumerating $DisplayName"

        if ($ReturnGroups) {
            $Mode = 'Groups'
        }
        elseif ($ReturnServicePrincipals) {
            $Mode = 'ServicePrincipals'
        }
        else {
            $Mode = 'Users'
        }

        $Output += Get-AzurePowerDirectoryRoleMembersRecursive -DirectoryRoleId $RoleId -Mode $Mode
    }

    end {
        $Output | Where-Object { $_ } | Sort-Object -Property ObjectId -Unique
    }
}

function Get-MgPrivilegedRolesMembers {
<#
.SYNOPSIS
Author: Jony Schats - 0xjs
Required Dependencies: Get-MgDirectoryRole, Get-MgDirectoryRoleMemberRecursive
Optional Dependencies: None

.DESCRIPTION
Recursively search through privileged Microsoft Entra roles and only return unique user objects.

.PARAMETER ReturnGroups
Return group objects instead of user objects.

.PARAMETER ReturnServicePrincipals
Return service principals instead of user objects.

.EXAMPLE
Get-MgPrivilegedRolesMembers

.EXAMPLE
Get-MgPrivilegedRolesMembers -ReturnGroups

.EXAMPLE
Get-MgPrivilegedRolesMembers -ReturnServicePrincipals
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$ReturnGroups,

        [Parameter(Mandatory = $false)]
        [switch]$ReturnServicePrincipals
    )

    begin {
        Assert-AzurePowerGraphConnection
        $Output = @()
        $ActiveRoles = @(Get-MgDirectoryRole -All -ErrorAction Stop)
    }

    process {
        foreach ($AdminRole in (Get-AzurePowerPrivilegedRoleNames)) {
            $AdminRoleData = $ActiveRoles | Where-Object { $_.DisplayName -ieq $AdminRole } | Select-Object -First 1
            Write-Verbose "Enumerating $($AdminRoleData.DisplayName)"

            if ($null -eq $AdminRoleData) {
                continue
            }

            if ($ReturnGroups) {
                $Output += $AdminRoleData | Get-MgDirectoryRoleMemberRecursive -ReturnGroups
            }
            elseif ($ReturnServicePrincipals) {
                $Output += $AdminRoleData | Get-MgDirectoryRoleMemberRecursive -ReturnServicePrincipals
            }
            else {
                $Output += $AdminRoleData | Get-MgDirectoryRoleMemberRecursive
            }
        }
    }

    end {
        $Output | Where-Object { $_ } | Sort-Object -Property ObjectId -Unique
    }
}

function Get-MgPrivilegedRolesOverview {
<#
.SYNOPSIS
Author: Jony Schats - 0xjs
Required Dependencies: Get-MgDirectoryRole, Get-MgDirectoryRoleMemberRecursive
Optional Dependencies: None

.DESCRIPTION
Recursively search through privileged Microsoft Entra roles and return an overview of the number of users, groups and service principals assigned to each role, including group and service principal owners.

.EXAMPLE
Get-MgPrivilegedRolesOverview
#>
    [CmdletBinding()]
    param()

    Assert-AzurePowerGraphConnection
    $Output = @()
    $ActiveRoles = @(Get-MgDirectoryRole -All -ErrorAction Stop)

    foreach ($AdminRole in (Get-AzurePowerPrivilegedRoleNames -OverviewSubset)) {
        $AdminRoleData = $ActiveRoles | Where-Object { $_.DisplayName -ieq $AdminRole } | Select-Object -First 1
        Write-Verbose "Enumerating $($AdminRoleData.DisplayName)"

        if ($null -eq $AdminRoleData) {
            $Output += [PSCustomObject]@{
                Role        = $AdminRole
                UserCount   = 0
                Users       = @()
                GroupCount  = 0
                Groups      = @()
                GroupOwners = @()
                SPsCount    = 0
                SPs         = @()
                SPsOwners   = @()
            }
            continue
        }

        $Users = @($AdminRoleData | Get-MgDirectoryRoleMemberRecursive | Sort-Object ObjectId -Unique)
        $Groups = @($AdminRoleData | Get-MgDirectoryRoleMemberRecursive -ReturnGroups | Sort-Object ObjectId -Unique)
        $ServicePrincipals = @($AdminRoleData | Get-MgDirectoryRoleMemberRecursive -ReturnServicePrincipals | Sort-Object ObjectId -Unique)

        $GroupOwners = @(
            foreach ($Group in $Groups) {
                Get-AzurePowerGroupOwners -GroupId $Group.ObjectId
            }
        ) | Where-Object { $_ } | Sort-Object ObjectId -Unique

        $ServicePrincipalOwners = @(
            foreach ($ServicePrincipal in $ServicePrincipals) {
                Get-AzurePowerServicePrincipalOwners -ServicePrincipalId $ServicePrincipal.ObjectId
            }
        ) | Where-Object { $_ } | Sort-Object ObjectId -Unique

        $Output += [PSCustomObject]@{
            Role        = $AdminRoleData.DisplayName
            UserCount   = $Users.Count
            Users       = @($Users.UserPrincipalName | Where-Object { $_ })
            GroupCount  = $Groups.Count
            Groups      = @($Groups.DisplayName | Where-Object { $_ })
            GroupOwners = @($GroupOwners | Get-AzurePowerOwnerLabel)
            SPsCount    = $ServicePrincipals.Count
            SPs         = @($ServicePrincipals.DisplayName | Where-Object { $_ })
            SPsOwners   = @($ServicePrincipalOwners | Get-AzurePowerOwnerLabel)
        }
    }

    $Output | Sort-Object -Property UserCount -Descending
}

function Get-MgDirectoryRoleOverview {
<#
.SYNOPSIS
Author: Jony Schats - 0xjs
Required Dependencies: Get-MgDirectoryRole, Get-MgDirectoryRoleMemberRecursive
Optional Dependencies: None

.DESCRIPTION
Recursively search through all active Microsoft Entra directory roles and return an overview of the number of users, groups and service principals assigned to each role, including group and service principal owners.

.EXAMPLE
Get-MgDirectoryRoleOverview
#>
    [CmdletBinding()]
    param()

    Assert-AzurePowerGraphConnection
    $Output = @()
    $ActiveRoles = @(Get-MgDirectoryRole -All -ErrorAction Stop)

    foreach ($RoleData in $ActiveRoles) {
        Write-Verbose "Enumerating $($RoleData.DisplayName)"

        $Users = @($RoleData | Get-MgDirectoryRoleMemberRecursive | Sort-Object ObjectId -Unique)
        $Groups = @($RoleData | Get-MgDirectoryRoleMemberRecursive -ReturnGroups | Sort-Object ObjectId -Unique)
        $ServicePrincipals = @($RoleData | Get-MgDirectoryRoleMemberRecursive -ReturnServicePrincipals | Sort-Object ObjectId -Unique)

        $GroupOwners = @(
            foreach ($Group in $Groups) {
                Get-AzurePowerGroupOwners -GroupId $Group.ObjectId
            }
        ) | Where-Object { $_ } | Sort-Object ObjectId -Unique

        $ServicePrincipalOwners = @(
            foreach ($ServicePrincipal in $ServicePrincipals) {
                Get-AzurePowerServicePrincipalOwners -ServicePrincipalId $ServicePrincipal.ObjectId
            }
        ) | Where-Object { $_ } | Sort-Object ObjectId -Unique

        $Output += [PSCustomObject]@{
            Role        = $RoleData.DisplayName
            UserCount   = $Users.Count
            Users       = @($Users.UserPrincipalName | Where-Object { $_ })
            GroupCount  = $Groups.Count
            Groups      = @($Groups.DisplayName | Where-Object { $_ })
            GroupOwners = @($GroupOwners | Get-AzurePowerOwnerLabel)
            SPsCount    = $ServicePrincipals.Count
            SPs         = @($ServicePrincipals.DisplayName | Where-Object { $_ })
            SPsOwners   = @($ServicePrincipalOwners | Get-AzurePowerOwnerLabel)
        }
    }

    $Output | Sort-Object -Property UserCount -Descending
}

function Get-MgPrivilegedObjects {
<#
.SYNOPSIS
Author: Jony Schats - 0xjs
Required Dependencies: Get-MgPrivilegedRolesMembers, Get-MgDirectoryRole, Get-MgDirectoryRoleMemberRecursive
Optional Dependencies: None

.DESCRIPTION
Recursively search through privileged Microsoft Entra roles and return unique users and service principal identities, including the owners of privileged groups and service principals.

.EXAMPLE
Get-MgPrivilegedObjects
#>
    [CmdletBinding()]
    param()

    Assert-AzurePowerGraphConnection

    $AllUsers = @()
    $AllServicePrincipals = @()

    $Users = @(Get-MgPrivilegedRolesMembers)
    $AllUsers += $Users
    Write-Host "[+] Discovered $($Users.Count) users"

    $Groups = @(Get-MgPrivilegedRolesMembers -ReturnGroups)
    $GroupOwners = @(
        foreach ($Group in $Groups) {
            Get-AzurePowerGroupOwners -GroupId $Group.ObjectId
        }
    ) | Where-Object { $_ } | Sort-Object ObjectId -Unique

    $AllUsers += @($GroupOwners | Where-Object { $_.ObjectType -eq 'User' })
    $AllServicePrincipals += @($GroupOwners | Where-Object { $_.ObjectType -eq 'ServicePrincipal' })
    Write-Host "[+] Discovered $($GroupOwners.Count) group owners"

    $ServicePrincipals = @(Get-MgPrivilegedRolesMembers -ReturnServicePrincipals)
    $AllServicePrincipals += $ServicePrincipals
    Write-Host "[+] Discovered $($ServicePrincipals.Count) service principals"

    $ServicePrincipalOwners = @(
        foreach ($ServicePrincipal in $ServicePrincipals) {
            Get-AzurePowerServicePrincipalOwners -ServicePrincipalId $ServicePrincipal.ObjectId
        }
    ) | Where-Object { $_ } | Sort-Object ObjectId -Unique

    $AllUsers += @($ServicePrincipalOwners | Where-Object { $_.ObjectType -eq 'User' })
    $AllServicePrincipals += @($ServicePrincipalOwners | Where-Object { $_.ObjectType -eq 'ServicePrincipal' })
    Write-Host "[+] Discovered $($ServicePrincipalOwners.Count) service principal owners"

    $AllUsers = @($AllUsers | Where-Object { $_ } | Sort-Object ObjectId -Unique)
    $AllServicePrincipals = @($AllServicePrincipals | Where-Object { $_ } | Sort-Object ObjectId -Unique)

    Write-Host "[+] Found $($AllUsers.Count) highly privileged users"
    Write-Host "[+] Found $($AllServicePrincipals.Count) highly privileged service principals"

    $AllUsers
    $AllServicePrincipals
}

function Get-MgUserMFAConfiguration {
<#
.SYNOPSIS
Author: Jony Schats - 0xjs
Required Dependencies: Get-MgUser, Get-MgReportAuthenticationMethodUserRegistrationDetail, Get-MgUserAuthenticationMethod, Invoke-MgGraphRequest
Optional Dependencies: None

.DESCRIPTION
Get MFA registration and authentication method information for a Microsoft Entra user. Requires a user from Get-MgUser or Get-MgPrivilegedRolesMembers as input.

The MFA Configured and MFA Capable fields are obtained from the Microsoft Graph userRegistrationDetails report. Detailed authentication method objects are retrieved with Get-MgUserAuthenticationMethod. The legacy per-user MFA state is retrieved from the Microsoft Graph beta authentication requirements endpoint.

.PARAMETER User
A user object returned by Get-MgUser or Get-MgPrivilegedRolesMembers, or another object containing an Id, ObjectId or UserPrincipalName property.

.PARAMETER Detailed
Include detailed registered authentication method objects and registered contact information.

.EXAMPLE
Get-MgUser -All | Get-MgUserMFAConfiguration
Get MFA configuration data for all users.

.EXAMPLE
Get-MgUser -All | Get-MgUserMFAConfiguration -Detailed
Get detailed MFA configuration data for all users.

.EXAMPLE
Get-MgPrivilegedRolesMembers | Get-MgUserMFAConfiguration
Get MFA configuration data for all users assigned to privileged roles.

.EXAMPLE
Get-MgPrivilegedRolesMembers | Get-MgUserMFAConfiguration -Detailed
Get detailed MFA configuration data for all users assigned to privileged roles.
#>
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        $User,

        [Parameter(Mandatory = $false)]
        [switch]$Detailed
    )

    begin {
        Assert-AzurePowerGraphConnection
        $Output = @()
    }

    process {
        $UserId = $null
        try {
            $UserId = Get-AzurePowerObjectId -InputObject $User
        }
        catch {
            $UserId = Get-AzurePowerPropertyValue -InputObject $User -Name @('UserPrincipalName', 'userPrincipalName')
        }

        if ([string]::IsNullOrWhiteSpace([string]$UserId)) {
            throw 'The supplied user object has no Id, ObjectId, or UserPrincipalName property.'
        }

        $GraphUser = Get-MgUser -UserId $UserId -Property @('Id', 'DisplayName', 'UserPrincipalName', 'AccountEnabled') -ErrorAction Stop
        $EscapedUserId = [uri]::EscapeDataString([string]$GraphUser.Id)

        try {
            $Registration = Get-MgReportAuthenticationMethodUserRegistrationDetail `
                -UserRegistrationDetailsId $GraphUser.Id `
                -ErrorAction Stop
        }
        catch {
            Write-Warning "Could not retrieve MFA registration details for $($GraphUser.UserPrincipalName): $($_.Exception.Message)"
            $Registration = $null
        }

        try {
            $AuthenticationRequirements = Invoke-MgGraphRequest `
                -Method GET `
                -Uri "https://graph.microsoft.com/beta/users/$EscapedUserId/authentication/requirements" `
                -ErrorAction Stop
        }
        catch {
            $AuthenticationRequirements = $null
        }

        $PreferredMethod = $null
        if ($null -ne $Registration) {
            $PreferredMethod = Get-AzurePowerPropertyValue -InputObject $Registration -Name @('UserPreferredMethodForSecondaryAuthentication', 'userPreferredMethodForSecondaryAuthentication')
        }

        $DefaultMethodMap = @{
            push                 = 'Microsoft Authenticator notification'
            oath                 = 'Authenticator code or OATH token'
            sms                  = 'SMS'
            voiceMobile          = 'Voice call (mobile)'
            voiceAlternateMobile = 'Voice call (alternate mobile)'
            voiceOffice          = 'Voice call (office)'
            none                 = '-'
            unknownFutureValue   = 'Unknown'
        }

        if ($PreferredMethod -and $DefaultMethodMap.ContainsKey([string]$PreferredMethod)) {
            $MfaDefaultMethod = $DefaultMethodMap[[string]$PreferredMethod]
        }
        elseif ($PreferredMethod) {
            $MfaDefaultMethod = [string]$PreferredMethod
        }
        else {
            $MfaDefaultMethod = '-'
        }

        $PerUserMfaState = $null
        if ($null -ne $AuthenticationRequirements) {
            $PerUserMfaState = Get-AzurePowerPropertyValue -InputObject $AuthenticationRequirements -Name @('perUserMfaState', 'PerUserMfaState')
        }
        if (-not $PerUserMfaState) {
            $PerUserMfaState = '-'
        }

        $MethodsRegistered = @()
        $SystemPreferredMethods = @()
        $IsMfaRegistered = $null
        $IsMfaCapable = $null
        $IsPasswordlessCapable = $null
        $IsSystemPreferredEnabled = $null
        $MfaReportUpdated = $null

        if ($null -ne $Registration) {
            $MethodsRegistered = @(Get-AzurePowerPropertyValue -InputObject $Registration -Name @('MethodsRegistered', 'methodsRegistered')) | Where-Object { $_ }
            $SystemPreferredMethods = @(Get-AzurePowerPropertyValue -InputObject $Registration -Name @('SystemPreferredAuthenticationMethods', 'systemPreferredAuthenticationMethods')) | Where-Object { $_ }
            $IsMfaRegistered = [bool](Get-AzurePowerPropertyValue -InputObject $Registration -Name @('IsMfaRegistered', 'isMfaRegistered'))
            $IsMfaCapable = [bool](Get-AzurePowerPropertyValue -InputObject $Registration -Name @('IsMfaCapable', 'isMfaCapable'))
            $IsPasswordlessCapable = [bool](Get-AzurePowerPropertyValue -InputObject $Registration -Name @('IsPasswordlessCapable', 'isPasswordlessCapable'))
            $IsSystemPreferredEnabled = [bool](Get-AzurePowerPropertyValue -InputObject $Registration -Name @('IsSystemPreferredAuthenticationMethodEnabled', 'isSystemPreferredAuthenticationMethodEnabled'))
            $MfaReportUpdated = Get-AzurePowerPropertyValue -InputObject $Registration -Name @('LastUpdatedDateTime', 'lastUpdatedDateTime')
        }

        # methodsRegistered can also contain SSPR-only methods such as email and
        # security questions. Keep the complete collection and expose a second,
        # filtered field for methods that can represent strong authentication.
        $MfaMethodsRegistered = @(
            $MethodsRegistered | Where-Object {
                $_ -notin @('email', 'securityQuestions', 'password')
            }
        )

        $Item = [PSCustomObject]@{
            UserPrincipalName            = $GraphUser.UserPrincipalName
            AccountEnabled               = $GraphUser.AccountEnabled
            'MFA Configured'             = $IsMfaRegistered
            'MFA Capable'                = $IsMfaCapable
            'MFA Methods'                = if ($IsMfaRegistered -and $MfaMethodsRegistered.Count -gt 0) { $MfaMethodsRegistered -join ', ' } else { '-' }
            'Registered Methods'         = if ($MethodsRegistered.Count -gt 0) { $MethodsRegistered -join ', ' } else { '-' }
            'MFA Default'                = $MfaDefaultMethod
            'System Preferred Enabled'   = $IsSystemPreferredEnabled
            'System Preferred Methods'   = if ($SystemPreferredMethods.Count -gt 0) { $SystemPreferredMethods -join ', ' } else { '-' }
            'Passwordless Capable'       = $IsPasswordlessCapable
            'Per-User MFA'               = [string]$PerUserMfaState
            'MFA Report Updated'         = $MfaReportUpdated
        }

        if ($Detailed) {
            try {
                $Methods = @(Get-MgUserAuthenticationMethod -UserId $GraphUser.Id -All -ErrorAction Stop)
            }
            catch {
                Write-Warning "Could not retrieve detailed authentication methods for $($GraphUser.UserPrincipalName): $($_.Exception.Message)"
                $Methods = @()
            }

            $MethodTypes = @(
                foreach ($Method in $Methods) {
                    Get-AzurePowerPropertyValue -InputObject $Method -Name @('@odata.type', 'ODataType')
                }
            ) | Where-Object { $_ }

            $PhoneMethods = @($Methods | Where-Object {
                (Get-AzurePowerPropertyValue -InputObject $_ -Name @('@odata.type', 'ODataType')) -eq '#microsoft.graph.phoneAuthenticationMethod'
            })

            $EmailMethod = $Methods | Where-Object {
                (Get-AzurePowerPropertyValue -InputObject $_ -Name @('@odata.type', 'ODataType')) -eq '#microsoft.graph.emailAuthenticationMethod'
            } | Select-Object -First 1

            $ReadableMethodTypes = @($MethodTypes | ForEach-Object {
                $_ -replace '^#microsoft\.graph\.', '' -replace 'AuthenticationMethod$', ''
            })

            $RegisteredPhoneNumbers = @(
                foreach ($PhoneMethod in $PhoneMethods) {
                    Get-AzurePowerPropertyValue -InputObject $PhoneMethod -Name @('PhoneNumber', 'phoneNumber')
                }
            ) | Where-Object { $_ }

            $RegisteredEmail = $null
            if ($EmailMethod) {
                $RegisteredEmail = Get-AzurePowerPropertyValue -InputObject $EmailMethod -Name @('EmailAddress', 'emailAddress')
            }

            $HasMobilePhone = $false
            foreach ($PhoneMethod in $PhoneMethods) {
                $PhoneType = Get-AzurePowerPropertyValue -InputObject $PhoneMethod -Name @('PhoneType', 'phoneType')
                if ($PhoneType -eq 'mobile') {
                    $HasMobilePhone = $true
                }
            }

            $PreferredAndSystemMethods = @($PreferredMethod) + @($SystemPreferredMethods)
            $HasSmsPreference = $PreferredAndSystemMethods -contains 'sms'
            $HasVoiceMobilePreference = $PreferredAndSystemMethods -contains 'voiceMobile'
            $HasPhoneAppOtp = ($MethodsRegistered -contains 'softwareOneTimePasscode') -or ($MethodsRegistered -contains 'hardwareOneTimePasscode')
            $HasPhoneAppNotification = $MethodsRegistered -contains 'microsoftAuthenticatorPush'

            $Item | Add-Member -NotePropertyName 'Authentication Method Objects' -NotePropertyValue $(if ($ReadableMethodTypes) { $ReadableMethodTypes -join ', ' } else { '-' })
            $Item | Add-Member -NotePropertyName MobilePhoneRegistered -NotePropertyValue $(if ($HasMobilePhone) { $true } else { '-' })
            $Item | Add-Member -NotePropertyName OneWaySMS -NotePropertyValue $(if ($HasSmsPreference) { $true } elseif ($HasMobilePhone) { 'Policy-dependent' } else { '-' })
            $Item | Add-Member -NotePropertyName TwoWayVoiceMobile -NotePropertyValue $(if ($HasVoiceMobilePreference) { $true } elseif ($HasMobilePhone) { 'Policy-dependent' } else { '-' })
            $Item | Add-Member -NotePropertyName PhoneAppOTP -NotePropertyValue $(if ($HasPhoneAppOtp) { $true } else { '-' })
            $Item | Add-Member -NotePropertyName PhoneAppNotification -NotePropertyValue $(if ($HasPhoneAppNotification) { $true } else { '-' })
            $Item | Add-Member -NotePropertyName 'Registered Email' -NotePropertyValue $(if ($RegisteredEmail) { $RegisteredEmail } else { '-' })
            $Item | Add-Member -NotePropertyName 'Registered Phone' -NotePropertyValue $(if ($RegisteredPhoneNumbers) { $RegisteredPhoneNumbers -join ', ' } else { '-' })
            $Item | Add-Member -NotePropertyName FIDO2 -NotePropertyValue $(if ($MethodTypes -contains '#microsoft.graph.fido2AuthenticationMethod') { $true } else { '-' })
            $Item | Add-Member -NotePropertyName WindowsHelloForBusiness -NotePropertyValue $(if ($MethodTypes -contains '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod') { $true } else { '-' })
            $Item | Add-Member -NotePropertyName TemporaryAccessPass -NotePropertyValue $(if ($MethodTypes -contains '#microsoft.graph.temporaryAccessPassAuthenticationMethod') { $true } else { '-' })
        }

        $Output += $Item
    }

    end {
        $Output
    }
}

# When imported as a script module, expose only the public Microsoft Graph commands.
if ($null -ne $ExecutionContext.SessionState.Module) {
    Export-ModuleMember -Function @(
        'Get-MgGroupMemberRecursive',
        'Get-MgDirectoryRoleMemberRecursive',
        'Get-MgPrivilegedRolesMembers',
        'Get-MgPrivilegedRolesOverview',
        'Get-MgDirectoryRoleOverview',
        'Get-MgPrivilegedObjects',
        'Get-MgUserMFAConfiguration'
    )
}
