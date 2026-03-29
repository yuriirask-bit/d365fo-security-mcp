from __future__ import annotations

from pydantic import BaseModel, Field


class SecurityRole(BaseModel):
    SecurityRoleIdentifier: str = Field(description="Unique identifier for the security role")
    SecurityRoleName: str = Field(description="Display name of the security role")
    Description: str = Field(default="", description="Description of the security role")
    UserLicenseType: str = Field(default="None", description="License type required for this role")
    AccessToSensitiveData: str = Field(
        default="", description="Indicates whether the role grants access to sensitive data"
    )


class UserRoleAssignment(BaseModel):
    UserId: str = Field(description="Identifier of the user")
    SecurityRoleIdentifier: str = Field(
        description="Identifier of the security role assigned to the user"
    )
    SecurityRoleName: str = Field(
        default="", description="Display name of the assigned security role"
    )
    AssignmentStatus: str = Field(
        default="Active", description="Status of the role assignment (e.g. Active, Disabled)"
    )
    AssignmentMode: str = Field(
        default="Direct", description="Mode of assignment (e.g. Direct, RuleBasedRoleAssignment)"
    )


class SecurityDuty(BaseModel):
    SecurityRoleIdentifier: str = Field(description="Identifier of the parent security role")
    SecurityRoleName: str = Field(
        default="", description="Display name of the parent security role"
    )
    SecurityDutyIdentifier: str = Field(description="Unique identifier for the security duty")
    SecurityDutyName: str = Field(default="", description="Display name of the security duty")
    SecurityPrivilegeIdentifier: str = Field(
        default="", description="Identifier of a privilege within the duty"
    )
    SecurityPrivilegeName: str = Field(
        default="", description="Display name of the privilege within the duty"
    )


class SecurityPrivilege(BaseModel):
    SecurityPrivilegeIdentifier: str = Field(
        description="Unique identifier for the security privilege"
    )
    SecurityPrivilegeName: str = Field(
        default="", description="Display name of the security privilege"
    )


class SystemUser(BaseModel):
    UserId: str = Field(description="Unique identifier of the system user")
    UserName: str = Field(default="", description="Display name of the system user")
    UserEmail: str = Field(default="", description="Email address of the system user")
    Enabled: bool = Field(default=True, description="Whether the user account is enabled")
    Company: str = Field(default="", description="Default company associated with the user")
