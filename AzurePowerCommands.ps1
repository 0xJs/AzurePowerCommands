Function Get-AzureADGroupMemberRecursive{
<#
.SYNOPSIS
Author: Jony Schats - 0xjs
Required Dependencies: Get-AzureADGroupMember
Optional Dependencies: None

.DESCRIPTION
Recursively search through groups and only return unique user objects. Requires the Get-AzureADGroup as input.

.EXAMPLE
Get-AzureADGroup -ObjectId <ID> | Get-AzureADGroupMemberRecursive

.EXAMPLE
Get-AzureADGroup | Where-Object -Property Displayname -eq "<GROUP>" | Get-AzureADGroupMemberRecursive
#>
	[cmdletbinding()]
	param(
	[parameter(Mandatory=$True,ValueFromPipeline=$true)]
	$AzureGroup
	)
		Begin{
			If(-not(Get-AzureADCurrentSessionInfo)){Connect-AzureAD}
			$Output = @()
		}
		Process {
			Write-Verbose -Message "Enumerating $($AzureGroup.DisplayName)"
			$Members = Get-AzureADGroupMember -ObjectId $AzureGroup.ObjectId -All $true
			$UserMembers = $Members | Where-Object{$_.ObjectType -eq 'User'}
			$Output += $UserMembers
			
			$GroupMembers = $Members | Where-Object{$_.ObjectType -eq 'Group'}
			If($GroupMembers){
				$UserMembers = $GroupMembers | ForEach-Object{ Get-AzureADGroupMemberRecursive -AzureGroup $_}
				$Output += $UserMembers
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

.EXAMPLE
Get-AzureADDirectoryRole -ObjectId <ID> | Get-AzureADDirectoryRoleMemberRecursive

.EXAMPLE
Get-AzureADDirectoryRole | Where-Object -Property Displayname -eq "<ROLE>" | Get-AzureADDirectoryRoleMemberRecursive
#>
	[cmdletbinding()]
	param(
	[parameter(Mandatory=$True,ValueFromPipeline=$true)]
	$RoleGroup
	)
		Begin{
			If(-not(Get-AzureADCurrentSessionInfo)){Connect-AzureAD}
			$Output = @()
		}
		Process {
			Write-Verbose -Message "Enumerating $($RoleGroup.DisplayName)"
			$Members = Get-AzureADDirectoryRoleMember -ObjectId $RoleGroup.ObjectId
			$UserMembers = $Members | Where-Object{$_.ObjectType -eq 'User'}
			$Output += $UserMembers
			
			$GroupMembers = $Members | Where-Object{$_.ObjectType -eq 'Group'}
			If($GroupMembers){
				$UserMembers = $GroupMembers | ForEach-Object{ Get-AzureADGroupMemberRecursive -AzureGroup $_}
				$Output += $UserMembers
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
Recursively search through privileged roles and only return unique user objects. Uses the roles "Security administrator", "Exchange Administrator", "Global administrator", "Conditional Access administrator", "SharePoint administrator", "Helpdesk administrator", "Billing administrator", "User administrator", "Authentication administrator"

.EXAMPLE
Get-AzureADPrivilegedRolesMembers

#>
    Begin{
        If(-not(Get-AzureADCurrentSessionInfo)){Connect-AzureAD}
		$AdminRoles = "Security administrator", "Exchange Administrator", "Global administrator", "Conditional Access administrator", "SharePoint administrator", "Helpdesk administrator", "Billing administrator", "User administrator", "Authentication administrator"
		$Output = @()
    }
	
	Process {
		foreach ($AdminRole in $AdminRoles) {			
			$AdminRoleData = Get-AzureADDirectoryRole | Where-Object -Property Displayname -eq $AdminRole
			Write-Verbose -Message "Enumerating $($AdminRoleData.DisplayName)"
			
			# If the role is populated
			if ($AdminRoleData -ne $null){
				
				# Retrieve members of the AdminRole
				$AdminRoleMembers = Get-AzureADDirectoryRole -ObjectId $AdminRoleData.ObjectId | Get-AzureADDirectoryRoleMemberRecursive
				$Output += $AdminRoleMembers
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
        If(-not(Get-AzureADCurrentSessionInfo)){Connect-AzureAD}
		$AdminRoles = "Security administrator", "Exchange Administrator", "Global administrator", "Conditional Access administrator", "SharePoint administrator", "Helpdesk administrator", "Billing administrator", "User administrator", "Authentication administrator"
		$Output = @()
    }
	
	Process {		
		foreach ($AdminRole in $AdminRoles) {
			$AdminRoleData = Get-AzureADDirectoryRole | Where-Object -Property Displayname -eq $AdminRole
			Write-Verbose -Message "Enumerating $($AdminRoleData.DisplayName)"

			# If the role is populated
			if ($AdminRoleData -ne $null){
				
				# Retrieve members of the AdminRole
				$AdminRoleMembers = Get-AzureADDirectoryRole -ObjectId $AdminRoleData.ObjectId | Get-AzureADDirectoryRoleMemberRecursive
				$AdminRoleMembersCount = $AdminRoleMembers | Sort-Object -Unique | Measure-Object
				
				$item = New-Object PSObject
				$item | Add-Member -type NoteProperty -Name 'Role' -Value $AdminRoleData.DisplayName
				$item | Add-Member -type NoteProperty -Name 'UserCount' -Value $AdminRoleMembersCount.Count
				$item | Add-Member -type NoteProperty -Name 'Members' -Value $AdminRoleMembers.UserPrincipalName
				$Output += $item
			}
			else {
				$item = New-Object PSObject
				$item | Add-Member -type NoteProperty -Name 'Role' -Value $AdminRole
				$item | Add-Member -type NoteProperty -Name 'UserCount' -Value "0"
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
        If(-not(Get-AzureADCurrentSessionInfo)){Connect-AzureAD}
		$Output = @()
    }
	
	Process {
		$AzureADRoles = Get-AzureADDirectoryRole

		foreach ($AzureADRole in $AzureADRoles) {
			Write-Verbose -Message "Enumerating $($AzureADRole.DisplayName)"
				
			# Retrieve members of the AdminRole
			$RoleMembers = Get-AzureADDirectoryRole -ObjectId $AzureADRole.ObjectId | Get-AzureADDirectoryRoleMemberRecursive
			$RoleMembersCount = $RoleMembers | Sort-Object -Unique | Measure-Object
			
			$item = New-Object PSObject
			$item | Add-Member -type NoteProperty -Name 'Role' -Value $AzureADRole.DisplayName
			$item | Add-Member -type NoteProperty -Name 'UserCount' -Value $RoleMembersCount.Count
			$item | Add-Member -type NoteProperty -Name 'Members' -Value $RoleMembers.UserPrincipalName
			$Output += $item
			}
	}

	end {
        Return $Output | Sort-Object -Property UserCount -Descending
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
			If(-not(Get-MsolUser)){Connect-MsolService}
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