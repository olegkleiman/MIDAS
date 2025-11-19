Design Document: Personal Information
Removal from JWT (MIDAS Project)

Version: 1.1

Author: Oleg Kleiman

Project: MIDAS / Digitel Ovdim Date: 2025-11-16
 
1.	Introduction
This document describes the proposed design for removing personal information from JWTs issued by the Digitel Ovdim authentication service. The goal is to ensure that no customer-related personal data is transmitted within the token itself. Instead, a server-generated identifier will be used, and sensitive information will be retrieved only through authenticated API calls.
This design applies only to Digitel Ovdim and does not extend to other systems such as MyDigitel, which use different authentication architectures.
 
2.	*b*Background and Motivation
Currently, the JWT tokens used by Digitel Ovdim include customer-related claims that expose personal information to client-side applications and network layers. This raises security and compliance concerns.
The proposed solution removes personal claims and replaces them with a server-managed GUID, ensuring that sensitive data is accessible only via secure, authenticated backend calls.
 
3.	Scope
3.1	In Scope
•	OAuth server changes (Digitel Ovdim authentication service)
•	Database schema changes for OTP and GUID storage
•	Token issuance and validation logic
•	Required Mobile Server changes
•	CI/CD and deployment processes
•	KeyVault and Managed Identity integration
3.2	Out of Scope
•	MyDigitel authentication flows
•	Azure B2C tokens and related cleansing
•	Changes to Ofek backend services
 
4.	Objectives
1.	Remove all personal information from issued JWT tokens.
2.	Replace user-identifiable data with a server-generated GUID stored in a secure backend.
3.	Ensure secure retrieval of user data through a dedicated endpoint ( /user_details ).
4.	Maintain compatibility with existing Ofek flows.
5.	Improve token security by migrating to RSA256 signing using Key Vault.
 
5.	Proposed Architecture
5.1	High-Level Flow
1.	User requests OTP via /api/otp .
2.	Server generates OTP + GUID pair and stores it in SQL.
3.	User requests token via /api/token .
4.	Server signs JWT with RSA256 from Key Vault; embeds GUID as sub claim.
5.	Client uses token to access Mobile Server APIs.
6.	Mobile Server validates JWT via /validate , obtains the stored GUID, and resolves the corresponding user ID.
7.	Mobile Server retrieves user details via /user_details when needed.
 
	6.	Detailed Design
6.1	Midas Server Changes
•	Migrate the service from .NET Framework 4.8 to .NET 8 Minimal API.
•	Introduce dependency injection and Managed Identity.
•	Integrate AppInsights with OpenTelemetry.
•	Update SQL schema to include GUID field for OTP entries.
•	Adjust stored procedures and data access layer.
•	Modify /api/otp? ?id=<>&phoneNum=<> GET request to generate and store GUID.
•	Modify /api/token to use insert the generated GUID to issued JWT as “sub” claim:
o	Fetch GUID from the database 
o	Issue JWT with RSA256 from Azure Key Vault
o	Store the GUID as the sub claim
•	Modify /api/refresh_token accordingly.
•	Update /validate to:
•	Validate RSA256-signed token
•	Extract sub and exchange it for the internal User ID • Apply GUIDUserID resolution logic to all relevant endpoints.
•	Deploy via CI/CD to Azure App Service.
•	Rotate and revoke symmetric signing key previously shared with Mobile Server.
6.2	Mobile Server Changes
•	Remove dependency on the nameid claim.
•	For any operation requiring User ID, call /user_details after validating the token.
•	Handle new failure modes:
 
 

7.	Non-Functional Requirements
•	Security: No personal data included in JWTs. All sensitive data transmitted only after authentication.
•	Performance: Additional round-trip to /user_details may increase latency; caching strategies may be considered.
•	Reliability: Mobile Server must handle token errors gracefully.
•	Compliance: Aligns with privacy and data minimization requirements.
 
8.	Risks and Mitigations
Risk	Impact	Mitigation
Increased dependency on network for / user_details	Medium	Implement retry logic and robust error handling
Incorrect handling of GUID/UserID exchange	High	Unit tests, integration tests, and monitoring
Clients still using personal claims	Medium	Communication plan and transition documentation
 
9.	Testing Strategy

 
10.	Deployment Plan
•	Prepare CI/CD pipelines
•	Deploy Midas server to Azure App Service (Web App) with Managed Identity
•	Perform configuration validation in staging
•	Deploy Mobile Server updates
•	Activate RSA256 signing and GUID-based tokens
 
11.	Open Questions / Pending Items
•	Confirm endpoint naming with Uzi’s team
•	Finalize database schema adjustments
•	Verify GUID lifecycle requirements
•	Confirm client readiness for new token structure
 
12.	Conclusion
This design provides a secure, scalable, and privacy-compliant approach for eliminating personal information from JWT tokens used by Digitel Ovdim. By adopting server-generated identifiers, centralizing sensitive-data access, and implementing strong cryptographic standards, the system becomes significantly more robust and secure.
 
End of Document
