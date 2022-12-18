Function Get-AzureADGroupMemberRecursive{
<#
.SYNOPSIS
Author: Jony Schats - 0xjs
Required Dependencies: Get-AzureADGroupMember
Optional Dependencies: None

.DESCRIPTION
Recursively search through groups and only return unique user objects. Requires the Get-AzureADGroup as input.

.PARAMETER ReturnGroups
Return group objects instead of user objects.

.PARAMETER ServicePrincipals
Return service principals instead of user objects.

.EXAMPLE
Get-AzureADGroup -ObjectId <ID> | Get-AzureADGroupMemberRecursive

.EXAMPLE
Get-AzureADGroup | Where-Object -Property Displayname -eq "<GROUP>" | Get-AzureADGroupMemberRecursive
#>
	[cmdletbinding()]
	param(
	[parameter(Mandatory=$True,ValueFromPipeline=$true)]
	$AzureGroup,
	[Parameter(Mandatory = $false)]
	[Switch]
	$ReturnGroups,
	[Parameter(Mandatory = $false)]
	[Switch]
	$ReturnServicePrincipals
	)
		Begin{
			# Check if Azure AD is loaded
			If(-not(Get-Command *Get-AzureADCurrentSessionInfo*)){
				Write-Host -ForegroundColor Red "AzureAD Module not imported, stopping"
				break
			}
			
			# Check connection with AzureAD
			try {
				$var = Get-AzureADTenantDetail
			}
			catch {
				Write-Host -ForegroundColor Red "You're not connected with AzureAD, Connect with Connect-AzureAD"
				break
			}
		
			$Output = @()
		}
		
		Process {
			Write-Verbose -Message "Enumerating $($AzureGroup.DisplayName)"
			$Members = Get-AzureADGroupMember -ObjectId $AzureGroup.ObjectId -All $true
			
			if ($ReturnGroups){
				$UserMembers = $Members | Where-Object{$_.ObjectType -eq 'Group'}
				$Output += $UserMembers
				
				$GroupMembers = $Members | Where-Object{$_.ObjectType -eq 'Group'}
				If($GroupMembers){
					$UserMembers = $GroupMembers | ForEach-Object{ Get-AzureADGroupMemberRecursive -ReturnGroups -AzureGroup $_}
					$Output += $UserMembers
				}
			}
			elseif ($ReturnServicePrincipals) {
				$UserMembers = $Members | Where-Object{$_.ObjectType -eq 'ServicePrincipal'}
				$Output += $UserMembers
				
				$GroupMembers = $Members | Where-Object{$_.ObjectType -eq 'Group'}
				If($GroupMembers){
					$UserMembers = $GroupMembers | ForEach-Object{ Get-AzureADGroupMemberRecursive -ReturnServicePrincipals -AzureGroup $_}
					$Output += $UserMembers
				}
			}
			else {
				$UserMembers = $Members | Where-Object{$_.ObjectType -eq 'User'}
				$Output += $UserMembers
				
				$GroupMembers = $Members | Where-Object{$_.ObjectType -eq 'Group'}
				If($GroupMembers){
					$UserMembers = $GroupMembers | ForEach-Object{ Get-AzureADGroupMemberRecursive -AzureGroup $_}
					$Output += $UserMembers
				}
			}
			
			
			
		}
		
		end {
			Return $Output | Sort-Object -Unique
		}
}

Function Get-AzureADDirectoryRoleMemberRecursive{
<#
.SYNOPSIS
Author: Jony Schats - 0xjs
Required Dependencies: Get-AzureADDirectoryRoleMember, Get-AzureADGroupMember, Get-AzureADGroupMemberRecursive
Optional Dependencies: None

.DESCRIPTION
Recursively search through roles and only return unique user objects. Requires the Get-AzureADDirectoryRole as input.

.PARAMETER ReturnGroups
Return group objects instead of user objects.

.PARAMETER ServicePrincipals
Return service principals instead of user objects.

.EXAMPLE
Get-AzureADDirectoryRole -ObjectId <ID> | Get-AzureADDirectoryRoleMemberRecursive

.EXAMPLE
Get-AzureADDirectoryRole | Where-Object -Property Displayname -eq "<ROLE>" | Get-AzureADDirectoryRoleMemberRecursive
#>
	[cmdletbinding()]
	param(
	[parameter(Mandatory=$True,ValueFromPipeline=$true)]
	$RoleGroup,
	[Parameter(Mandatory = $false)]
	[Switch]
	$ReturnGroups,
	[Parameter(Mandatory = $false)]
	[Switch]
	$ReturnServicePrincipals
	)
		Begin{
			# Check if Azure AD is loaded
			If(-not(Get-Command *Get-AzureADCurrentSessionInfo*)){
				Write-Host -ForegroundColor Red "AzureAD Module not imported, stopping"
				break
			}
			
			# Check connection with AzureAD
			try {
				$var = Get-AzureADTenantDetail
			}
			catch {
				Write-Host -ForegroundColor Red "You're not connected with AzureAD, Connect with Connect-AzureAD"
				break
			}
		
			$Output = @()
		}
		
		Process {
			Write-Verbose -Message "Enumerating $($RoleGroup.DisplayName)"
			$Members = Get-AzureADDirectoryRoleMember -ObjectId $RoleGroup.ObjectId
			
			if ($ReturnGroups){
				$UserMembers = $Members | Where-Object{$_.ObjectType -eq 'Group'}
				$Output += $UserMembers
				
				$GroupMembers = $Members | Where-Object{$_.ObjectType -eq 'Group'}
				If($GroupMembers){
					$UserMembers = $GroupMembers | ForEach-Object{ Get-AzureADGroupMemberRecursive -ReturnGroups -AzureGroup $_}
					$Output += $UserMembers
				}
			}
			elseif ($ReturnServicePrincipals) {
				$UserMembers = $Members | Where-Object{$_.ObjectType -eq 'ServicePrincipal'}
				$Output += $UserMembers
				
				$GroupMembers = $Members | Where-Object{$_.ObjectType -eq 'Group'}
				If($GroupMembers){
					$UserMembers = $GroupMembers | ForEach-Object{ Get-AzureADGroupMemberRecursive -ReturnServicePrincipals -AzureGroup $_}
					$Output += $UserMembers
				}
			}
			else {
				$UserMembers = $Members | Where-Object{$_.ObjectType -eq 'User'}
				$Output += $UserMembers
				
				$GroupMembers = $Members | Where-Object{$_.ObjectType -eq 'Group'}
				If($GroupMembers){
					$UserMembers = $GroupMembers | ForEach-Object{ Get-AzureADGroupMemberRecursive -AzureGroup $_}
					$Output += $UserMembers
				}
			}
		}
		
		end {
			Return $Output | Sort-Object -Unique
		}
}

Function Get-AzureADPrivilegedRolesMembers{
<#
.SYNOPSIS
Author: Jony Schats - 0xjs
Required Dependencies: Get-AzureADDirectoryRole, Get-AzureADDirectoryRoleMember, Get-AzureADGroupMember, Get-AzureADGroupMemberRecursive
Optional Dependencies: None

.DESCRIPTION
Recursively search through privileged roles and only return unique user objects.

.PARAMETER ReturnGroups
Return group objects instead of user objects.

.PARAMETER ServicePrincipals
Return service principals instead of user objects.

.EXAMPLE
Get-AzureADPrivilegedRolesMembers

#>
	[cmdletbinding()]
	param(
	[Parameter(Mandatory = $false)]
	[Switch]
	$ReturnGroups,
	[Parameter(Mandatory = $false)]
	[Switch]
	$ReturnServicePrincipals
	)
	
    Begin{
		# Check if Azure AD is loaded
		If(-not(Get-Command *Get-AzureADCurrentSessionInfo*)){
			Write-Host -ForegroundColor Red "AzureAD Module not imported, stopping"
			break
		}
        
		# Check connection with AzureAD
		try {
			$var = Get-AzureADTenantDetail
		}
		catch {
			Write-Host -ForegroundColor Red "You're not connected with AzureAD, Connect with Connect-AzureAD"
			break
		}
		
		$AdminRoles = "Global administrator", "Application administrator", "Authentication Administrator", "Billing administrator", "Cloud application administrator", "Conditional Access administrator", "Exchange administrator", "Helpdesk administrator", "Password administrator", "Privileged authentication administrator", "Privileged Role Administrator", "Security administrator", "SharePoint administrator", "User administrator"
		$Output = @()
    }
	
	Process {
		foreach ($AdminRole in $AdminRoles) {			
			$AdminRoleData = Get-AzureADDirectoryRole | Where-Object -Property Displayname -eq $AdminRole
			Write-Verbose -Message "Enumerating $($AdminRoleData.DisplayName)"
			
			# If the role is populated
			if ($AdminRoleData -ne $null){
				if ($ReturnGroups){
					$AdminRoleMembers = Get-AzureADDirectoryRole -ObjectId $AdminRoleData.ObjectId | Get-AzureADDirectoryRoleMemberRecursive -ReturnGroups
					$Output += $AdminRoleMembers
				}
				elseif ($ReturnServicePrincipals) {
					$AdminRoleMembers = Get-AzureADDirectoryRole -ObjectId $AdminRoleData.ObjectId | Get-AzureADDirectoryRoleMemberRecursive -ReturnServicePrincipals
					$Output += $AdminRoleMembers
				}
				else {
					$AdminRoleMembers = Get-AzureADDirectoryRole -ObjectId $AdminRoleData.ObjectId | Get-AzureADDirectoryRoleMemberRecursive
					$Output += $AdminRoleMembers
				}
			}
		}
	}

	end {
        Return $Output | Sort-Object -Unique
    }
}

Function Get-AzureADPrivilegedRolesOverview{
<#
.SYNOPSIS
Author: Jony Schats - 0xjs
Required Dependencies: Get-AzureADDirectoryRole, Get-AzureADDirectoryRoleMember, Get-AzureADGroupMember, Get-AzureADGroupMemberRecursive
Optional Dependencies: None

.DESCRIPTION
Recursively search through privileged Azure AD roles and return a overview of the amount of members a role has and the members itself.

.EXAMPLE
Get-AzureADPrivilegedRolesOverview

#>
    Begin{
		# Check if Azure AD is loaded
		If(-not(Get-Command *Get-AzureADCurrentSessionInfo*)){
			Write-Host -ForegroundColor Red "AzureAD Module not imported, stopping"
			break
		}
        
		# Check connection with AzureAD
		try {
			$var = Get-AzureADTenantDetail
		}
		catch {
			Write-Host -ForegroundColor Red "You're not connected with AzureAD, Connect with Connect-AzureAD"
			break
		}
		
		$AdminRoles = "Global administrator", "Application administrator", "Authentication Administrator", "Billing administrator", "Cloud application administrator", "Conditional Access administrator", "Exchange administrator", "Helpdesk administrator", "Password administrator", "Privileged authentication administrator", "Privileged Role Administrator", "Security administrator", "SharePoint administrator", "User administrator"
		$Output = @()
    }
	
	Process {		
		foreach ($AdminRole in $AdminRoles) {
			$AdminRoleData = Get-AzureADDirectoryRole | Where-Object -Property Displayname -eq $AdminRole
			Write-Verbose -Message "Enumerating $($AdminRoleData.DisplayName)"

			# If the role is populated
			if ($AdminRoleData -ne $null){
				
				# Retrieve members of the AdminRole
				$AdminRoleMembersUsers = Get-AzureADDirectoryRole -ObjectId $AdminRoleData.ObjectId | Get-AzureADDirectoryRoleMemberRecursive
				$AdminRoleMembersUsersCount = $AdminRoleMembersUsers | Sort-Object -Unique | Measure-Object
				
				$AdminRoleMembersGroups = Get-AzureADDirectoryRole -ObjectId $AdminRoleData.ObjectId | Get-AzureADDirectoryRoleMemberRecursive -ReturnGroups
				$AdminRoleMembersGroupsCount = $AdminRoleMembersGroups | Sort-Object -Unique | Measure-Object
				$GroupOwners = Get-AzureADDirectoryRole -ObjectId $AdminRoleData.ObjectId | Get-AzureADDirectoryRoleMemberRecursive -ReturnGroups | Get-AzureADGroupOwner
				
				$AdminRoleMembersSPs = Get-AzureADDirectoryRole -ObjectId $AdminRoleData.ObjectId | Get-AzureADDirectoryRoleMemberRecursive -ReturnServicePrincipals
				$AdminRoleMembersSPsCount = $AdminRoleMembersSPs | Sort-Object -Unique | Measure-Object
				$ServicePrincipalOwners = Get-AzureADDirectoryRole -ObjectId $AdminRoleData.ObjectId | Get-AzureADDirectoryRoleMemberRecursive -ReturnServicePrincipals | Get-AzureADServicePrincipalOwner
				
				$item = New-Object PSObject
				$item | Add-Member -type NoteProperty -Name 'Role' -Value $AdminRoleData.DisplayName
				
				$item | Add-Member -type NoteProperty -Name 'UserCount' -Value $AdminRoleMembersUsersCount.Count
				$item | Add-Member -type NoteProperty -Name 'Users' -Value $AdminRoleMembersUsers.UserPrincipalName
				
				$item | Add-Member -type NoteProperty -Name 'GroupCount' -Value $AdminRoleMembersGroupsCount.Count
				$item | Add-Member -type NoteProperty -Name 'Groups' -Value $AdminRoleMembersGroups.DisplayName
				$item | Add-Member -type NoteProperty -Name 'GroupOwners' -Value $GroupOwners.UserPrincipalName
				
				$item | Add-Member -type NoteProperty -Name 'SPsCount' -Value $AdminRoleMembersSPsCount.Count
				$item | Add-Member -type NoteProperty -Name 'SPs' -Value $AdminRoleMembersSPs.DisplayName
				$item | Add-Member -type NoteProperty -Name 'SPsOwners' -Value $ServicePrincipalOwners.UserPrincipalName
				
				$Output += $item
			}
			else {
				$item = New-Object PSObject
				$item | Add-Member -type NoteProperty -Name 'Role' -Value $AdminRole
				$item | Add-Member -type NoteProperty -Name 'UserCount' -Value "0"
				$item | Add-Member -type NoteProperty -Name 'GroupCount' -Value "0"
				$item | Add-Member -type NoteProperty -Name 'SPsCount' -Value "0"
				$Output += $item
			}
		}
	}

	end {
        Return $Output | Sort-Object -Property UserCount -Descending
    }
}

Function Get-AzureADDirectoryRoleOverview{
<#
.SYNOPSIS
Author: Jony Schats - 0xjs
Required Dependencies: Get-AzureADDirectoryRole, Get-AzureADDirectoryRoleMember, Get-AzureADGroupMember, Get-AzureADGroupMemberRecursive
Optional Dependencies: None

.DESCRIPTION
Recursively search through all active Azure AD roles and return a overview of the amount of members a role has and the members itself.

.EXAMPLE
Get-AzureADDirectoryRoleOverview

#>
    Begin{
        		# Check if Azure AD is loaded
		If(-not(Get-Command *Get-AzureADCurrentSessionInfo*)){
			Write-Host -ForegroundColor Red "AzureAD Module not imported, stopping"
			break
		}
        
		# Check connection with AzureAD
		try {
			$var = Get-AzureADTenantDetail
		}
		catch {
			Write-Host -ForegroundColor Red "You're not connected with AzureAD, Connect with Connect-AzureAD"
			break
		}
		
		$Output = @()
    }
	
	Process {
		$AzureADRoles = Get-AzureADDirectoryRole

		foreach ($RoleData in $AzureADRoles) {
			Write-Verbose -Message "Enumerating $($RoleData.DisplayName)"
				
			$RoleMembersUsers = Get-AzureADDirectoryRole -ObjectId $RoleData.ObjectId | Get-AzureADDirectoryRoleMemberRecursive
			$RoleMembersUsersCount = $RoleMembersUsers | Sort-Object -Unique | Measure-Object
			
			$RoleMembersGroups = Get-AzureADDirectoryRole -ObjectId $RoleData.ObjectId | Get-AzureADDirectoryRoleMemberRecursive -ReturnGroups
			$RoleMembersGroupsCount = $RoleMembersGroups | Sort-Object -Unique | Measure-Object
			$GroupOwners = Get-AzureADDirectoryRole -ObjectId $RoleData.ObjectId | Get-AzureADDirectoryRoleMemberRecursive -ReturnGroups | Get-AzureADGroupOwner
			
			$RoleMembersSPs = Get-AzureADDirectoryRole -ObjectId $RoleData.ObjectId | Get-AzureADDirectoryRoleMemberRecursive -ReturnServicePrincipals
			$RoleMembersSPsCount = $RoleMembersSPs | Sort-Object -Unique | Measure-Object
			$ServicePrincipalOwners = Get-AzureADDirectoryRole -ObjectId $RoleData.ObjectId | Get-AzureADDirectoryRoleMemberRecursive -ReturnServicePrincipals | Get-AzureADServicePrincipalOwner
			
			$item = New-Object PSObject
			$item | Add-Member -type NoteProperty -Name 'Role' -Value $RoleData.DisplayName
			
			$item | Add-Member -type NoteProperty -Name 'UserCount' -Value $RoleMembersUsersCount.Count
			$item | Add-Member -type NoteProperty -Name 'Users' -Value $RoleMembersUsers.UserPrincipalName
			
			$item | Add-Member -type NoteProperty -Name 'GroupCount' -Value $RoleMembersGroupsCount.Count
			$item | Add-Member -type NoteProperty -Name 'Groups' -Value $RoleMembersGroups.DisplayName
			$item | Add-Member -type NoteProperty -Name 'GroupOwners' -Value $GroupOwners.UserPrincipalName
			
			$item | Add-Member -type NoteProperty -Name 'SPsCount' -Value $RoleMembersSPsCount.Count
			$item | Add-Member -type NoteProperty -Name 'SPs' -Value $RoleMembersSPs.DisplayName
			$item | Add-Member -type NoteProperty -Name 'SPsOwners' -Value $ServicePrincipalOwners.UserPrincipalName
			
			$Output += $item
			}
	}

	end {
        Return $Output | Sort-Object -Property UserCount -Descending
    }
}

Function Get-AzureADPrivilegedIdentities{
<#
.SYNOPSIS
Author: Jony Schats - 0xjs
Required Dependencies: Get-AzureADPrivilegedRolesMembers, Get-AzureADDirectoryRole, Get-AzureADDirectoryRoleMember, Get-AzureADGroupMember, Get-AzureADGroupMemberRecursive
Optional Dependencies: None

.DESCRIPTION
Recursively search through privileged roles and return users and service principal identities and their owners

.EXAMPLE
Get-AzureADPrivilegedIdentities

#>
	[cmdletbinding()]
	param(

	)
	
    Begin{
		# Check if Azure AD is loaded
		If(-not(Get-Command *Get-AzureADCurrentSessionInfo*)){
			Write-Host -ForegroundColor Red "AzureAD Module not imported, stopping"
			break
		}
        
		# Check connection with AzureAD
		try {
			$var = Get-AzureADTenantDetail
		}
		catch {
			Write-Host -ForegroundColor Red "You're not connected with AzureAD, Connect with Connect-AzureAD"
			break
		}
		
		$AllUsers = @()
		$AllServicePrincipals = @()
		$Output = @()
    }
	
	Process {
		# Retrieving privileged users member of role
		$Users = Get-AzureADPrivilegedRolesMembers
		$AllUsers += $users
		$UsersCount = ($Users | Measure-Object).count
		Write-Host "[+] Discovered $UsersCount users"
		
		# Retrieving privileged group owners
		$GroupOwners = Get-AzureADPrivilegedRolesMembers -ReturnGroup | Get-AzureADGroupOwner
		$AllUsers += $GroupOwners | Where-Object -Property ObjectType -Match User
		$AllServicePrincipals += $GroupOwners | Where-Object -Property ObjectType -Match ServicePrincipal
		$CountGroupOwners = ($Users | Measure-Object).count
		Write-Host "[+] Discovered $CountGroupOwners group owners"
		
		# Retrieving privileged service principals
		$ServicePrincipals = Get-AzureADPrivilegedRolesMembers -ReturnServicePrincipals
		$AllServicePrincipals += $ServicePrincipals
		$CountServicePrincipals = ($ServicePrincipals | Measure-Object).count
		Write-Host "[+] Discovered $CountServicePrincipals service principals"
		
		# Retrieving privileged service principal owners
		$ServicePrincipalOwners = Get-AzureADPrivilegedRolesMembers -ReturnServicePrincipals | Get-AzureADServicePrincipalOwner
		$AllUsers += $ServicePrincipalOwners
		$CountServicePrincipalOwners = ($ServicePrincipalOwners | Measure-Object).count
		Write-Host "[+] Discovered $CountServicePrincipalOwners service principal owners"
		
		$CountAllUsers = ($AllUsers | Measure-Object).count
		Write-Host "[+] Found $CountAllUsers highly privileged users"
		$CountAllServicePrincipals = ($AllServicePrincipals | Measure-Object).count
		Write-Host "[+] Found $CountAllServicePrincipals highly privileged service principals"
		
		$AllUsers = $AllUsers | Sort-Object -Unique
		$AllServicePrincipals = $AllServicePrincipals | Sort-Object -Unique
		
		$Output += $AllUsers
		$Output += $AllServicePrincipals
	}

	end {
		return $Output | ft -Force
    }
}

Function Get-AzureADUserMFAConfiguration{
<#
.SYNOPSIS
Author: Jony Schats - 0xjs
Required Dependencies: Get-MsolUser
Optional Dependencies: None

.DESCRIPTION
Get MFA configuration data for the user. Requires a user as input.

.PARAMETER Detailed
If specified will create detailed MFA configuration objects

.EXAMPLE
Get-AzureADUser | Get-AzureADUserMFAConfiguration
Get MFA configuration data of all users

.EXAMPLE
Get-MsolUser | Get-AzureADUserMFAConfiguration
Get MFA configuration data of all users

.EXAMPLE
Get-MsolUser | Get-AzureADUserMFAConfiguration -Detailed
Get detailed MFA configuration data of all users

.EXAMPLE
Get-AzureADPrivilegedRolesMembers | Get-AzureADUserMFAConfiguration
Get MFA configuration data for all users of privileges roles

.EXAMPLE
Get-AzureADPrivilegedRolesMembers | Get-AzureADUserMFAConfiguration -Detailed
Get detailed MFA configuration data for all users of privileges roles
#>
	[OutputType('System.Management.Automation.PSCustomObject')]
	[cmdletbinding()]
	param(
	[parameter(Mandatory=$True,ValueFromPipeline=$true)]
	$User,
	[Parameter(Mandatory = $false)]
	[Switch]
	$Detailed
	)
		Begin{
			# Check if MSOnline is loaded
			If(-not(Get-Command *Get-MsolCompanyInformation*)){
				Write-Host -ForegroundColor Red "MSOnline Module not imported, stopping"
				break
			}
			
			# Check connection with MSOnline
			try {
				$var = Get-MsolDomain -ErrorAction Stop > $null
			}
			catch {
				Write-Host -ForegroundColor Red "You're not connected with MSOnline, Connect with Connect-MsolService"
				break
			}
		
			$Output = @()
		}
		
		Process {
			$User = Get-MsolUser -ObjectId $_.ObjectId 
			
			$MFADefault = ""
			$MFAConfigured = ""
			$MFADefaultMethod = ""
				
			$MFADefault = $User.StrongAuthenticationMethods | Where-Object -Property IsDefault -EQ $True | Select-Object -ExpandProperty MethodType
			
			if ($User.StrongAuthenticationMethods) {
				$MFAConfigured = $true
			}
			else {
				$MFAConfigured = $false
			}

			if ($MFADefault -eq "PhoneAppNotification") {
				$MFADefaultMethod = "Microsoft Authenticator"
			}
			elseif ($MFADefault -eq "PhoneAppOTP") {
				$MFADefaultMethod = "HW token / Authenticator"
			}
			elseif ($MFADefault -eq "OneWaySMS") {
				$MFADefaultMethod = "SMS"
			}
			elseif ($MFADefault -eq "TwoWayVoiceMobile") {
				$MFADefaultMethod = "Voice"
			}
			
			$item = New-Object PSObject
			$item | Add-Member -type NoteProperty -Name 'UserPrincipalName' -Value $User.UserPrincipalName
			$item | Add-Member -type NoteProperty -Name 'MFA Configured' -Value $MFAConfigured
			$item | Add-Member -type NoteProperty -Name 'MFA Default' -Value $MFADefaultMethod
			
			if ($User.StrongAuthenticationRequirements) {
					$item | Add-Member -type NoteProperty -Name 'Per-User MFA' -Value $User.StrongAuthenticationRequirements.State
				} else {
					$item | Add-Member -type NoteProperty -Name 'Per-User MFA' -Value "-"
			}
			
			if ($Detailed){
				if ($User.StrongAuthenticationMethods.MethodType -contains "OneWaySMS") {
				$item | Add-Member -type NoteProperty -Name 'OneWaySMS' -Value $true
				} else {
					$item | Add-Member -type NoteProperty -Name 'OneWaySMS' -Value "-"
				}
				
				if ($User.StrongAuthenticationMethods.MethodType -contains "TwoWayVoiceMobile") {
					$item | Add-Member -type NoteProperty -Name 'TwoWayVoiceMobile' -Value $true
				} else {
					$item | Add-Member -type NoteProperty -Name 'TwoWayVoiceMobile' -Value "-"
				}
				
				if ($User.StrongAuthenticationMethods.MethodType -contains "PhoneAppOTP") {
					$item | Add-Member -type NoteProperty -Name 'PhoneAppOTP' -Value $true
				} else {
					$item | Add-Member -type NoteProperty -Name 'PhoneAppOTP' -Value "-"
				}
				
				if ($User.StrongAuthenticationMethods.MethodType -contains "PhoneAppNotification") {
					$item | Add-Member -type NoteProperty -Name 'PhoneAppNotification' -Value $true
				} else {
					$item | Add-Member -type NoteProperty -Name 'PhoneAppNotification' -Value "-"
				}
				
				if ($User.StrongAuthenticationUserDetails.Email) {
					$item | Add-Member -type NoteProperty -Name 'Registered Email' -Value $User.StrongAuthenticationUserDetails.Email
				} else {
					$item | Add-Member -type NoteProperty -Name 'Registered Email' -Value "-"
				}
				
				if ($User.StrongAuthenticationUserDetails.PhoneNumber) {
					$item | Add-Member -type NoteProperty -Name 'Registered Phone' -Value $User.StrongAuthenticationUserDetails.PhoneNumber
				} else {
					$item | Add-Member -type NoteProperty -Name 'Registered Phone' -Value "-"
				}
			}
			
			$Output += $item
		}

		end {
			$Output
		}
}
