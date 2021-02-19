
Feature: Attributes 

Background:
* def mainUrl = attributes_url

@ignore
Scenario: Fetch all attributes without bearer token 
	Given url mainUrl 
	When method GET 
	Then status 401 

@ignore
Scenario: Fetch all attributes 
	Given url mainUrl 
	And print 'accessToken = '+accessToken
	And print 'issuer = '+issuer
	And header Authorization = 'Bearer ' + 'eyJraWQiOiJiZTMwZTY4ZC1lZGI5LTRhNzAtOTU0OS03NDFiYmRiYWY4OGFfc2lnX3JzMjU2IiwidHlwIjoiSldUIiwiYWxnIjoiUlMyNTYifQ.eyJhdWQiOiJiNmNjOWFkYS1jYTBhLTQyOTQtOWJiZS0yMmNjZWQyOWU5MjEiLCJzdWIiOiJnT0pveU9xUDRrVkJQTDZmRktha1JQVTRrS2dlbExsN1FfNXRkNHgyS09ZIiwieDV0I1MyNTYiOiIiLCJjb2RlIjoiN2Q1NTczZDctMDFlNy00MzA2LThhMTYtYWUyNDU2M2ViNDJiIiwic2NvcGUiOlsiaHR0cHM6Ly9qYW5zLmlvL29hdXRoL2NvbmZpZy9hdHRyaWJ1dGVzLnJlYWRvbmx5IiwiaHR0cHM6Ly9qYW5zLmlvL29hdXRoL2NvbmZpZy9hY3JzLnJlYWRvbmx5IiwiaHR0cHM6Ly9qYW5zLmlvL29hdXRoL2NvbmZpZy9zY29wZXMucmVhZG9ubHkiLCJodHRwczovL2phbnMuaW8vb2F1dGgvY29uZmlnL3NjcmlwdHMucmVhZG9ubHkiLCJodHRwczovL2phbnMuaW8vb2F1dGgvY29uZmlnL2NsaWVudHMucmVhZG9ubHkiLCJodHRwczovL2phbnMuaW8vb2F1dGgvY29uZmlnL3NtdHAucmVhZG9ubHkiLCJodHRwczovL2phbnMuaW8vb2F1dGgvY29uZmlnL2xvZ2dpbmcucmVhZG9ubHkiLCJodHRwczovL2phbnMuaW8vb2F1dGgvY29uZmlnL3VtYS9yZXNvdXJjZXMucmVhZG9ubHkiLCJodHRwczovL2phbnMuaW8vb2F1dGgvY29uZmlnL2RhdGFiYXNlL2xkYXAucmVhZG9ubHkiLCJodHRwczovL2phbnMuaW8vb2F1dGgvY29uZmlnL2p3a3MucmVhZG9ubHkiLCJodHRwczovL2phbnMuaW8vb2F1dGgvY29uZmlnL2ZpZG8yLnJlYWRvbmx5IiwiaHR0cHM6Ly9qYW5zLmlvL29hdXRoL2NvbmZpZy9jYWNoZS5yZWFkb25seSIsImh0dHBzOi8vamFucy5pby9vYXV0aC9qYW5zLWF1dGgtc2VydmVyL2NvbmZpZy9wcm9wZXJ0aWVzLnJlYWRvbmx5IiwiaHR0cHM6Ly9qYW5zLmlvL29hdXRoL2NvbmZpZy9kYXRhYmFzZS9jb3VjaGJhc2UucmVhZG9ubHkiXSwiaXNzIjoiaHR0cHM6Ly9jZS1kZXY2LmdsdXUub3JnIiwidG9rZW5fdHlwZSI6ImJlYXJlciIsImV4cCI6MTYxMzY2NzQ1NCwiaWF0IjoxNjEzNjY3MTU0LCJjbGllbnRfaWQiOiJiNmNjOWFkYS1jYTBhLTQyOTQtOWJiZS0yMmNjZWQyOWU5MjEifQ.pgZ7kqZMvPTpO5U0ZjX8wteJ9XzlFDGUYIMy16uPCNkpHMr5u_usFd5uyc44gM5eyDOBmuARu0cgo2wIuLTahoNchHl3JtHzvu1z9m-S6WCdsfHWB4XZnR6pdtbTLMs8CL8D4rY2b05qBHB-XQf5aN9MijrLQCBPxkDclh_EQRDH5EEff2nOSaIr9r1ElgXHAYnvteY465NGndxh90w3lAXyvK5ys0e8E9k4vAU6rhsrcFIXihuKlzTdQDJW-hqg4NwCTIxWGef1oVo2zuhx5TFaRKOCdb4F2aWzy2-zDmKb2F_OSLuKRMeZQ_b3SAQ7bd-F87bGISr3tSlsuIGeOQ'
	#And header issuer = issuer  
	When method GET 
	Then status 200 
	And print response
	And assert response.length != null 
	And assert response.length >= 10 


Scenario: Fetch the first three attributes 
	Given url mainUrl
	#And header Authorization = 'Bearer ' + accessToken
	And header Authorization = 'Bearer ' + 'eyJraWQiOiJiZTMwZTY4ZC1lZGI5LTRhNzAtOTU0OS03NDFiYmRiYWY4OGFfc2lnX3JzMjU2IiwidHlwIjoiSldUIiwiYWxnIjoiUlMyNTYifQ.eyJhdWQiOiJiNmNjOWFkYS1jYTBhLTQyOTQtOWJiZS0yMmNjZWQyOWU5MjEiLCJzdWIiOiJnT0pveU9xUDRrVkJQTDZmRktha1JQVTRrS2dlbExsN1FfNXRkNHgyS09ZIiwieDV0I1MyNTYiOiIiLCJjb2RlIjoiZDMzYzM1MzYtYzM0Zi00MzY1LTg0NDUtMDIyMjc3MTkyNzJkIiwic2NvcGUiOlsiaHR0cHM6Ly9qYW5zLmlvL29hdXRoL2NvbmZpZy9hdHRyaWJ1dGVzLnJlYWRvbmx5IiwiaHR0cHM6Ly9qYW5zLmlvL29hdXRoL2NvbmZpZy9hY3JzLnJlYWRvbmx5IiwiaHR0cHM6Ly9qYW5zLmlvL29hdXRoL2NvbmZpZy9zY29wZXMucmVhZG9ubHkiLCJodHRwczovL2phbnMuaW8vb2F1dGgvY29uZmlnL3NjcmlwdHMucmVhZG9ubHkiLCJodHRwczovL2phbnMuaW8vb2F1dGgvY29uZmlnL2NsaWVudHMucmVhZG9ubHkiLCJodHRwczovL2phbnMuaW8vb2F1dGgvY29uZmlnL3NtdHAucmVhZG9ubHkiLCJodHRwczovL2phbnMuaW8vb2F1dGgvY29uZmlnL2xvZ2dpbmcucmVhZG9ubHkiLCJodHRwczovL2phbnMuaW8vb2F1dGgvY29uZmlnL3VtYS9yZXNvdXJjZXMucmVhZG9ubHkiLCJodHRwczovL2phbnMuaW8vb2F1dGgvY29uZmlnL2RhdGFiYXNlL2xkYXAucmVhZG9ubHkiLCJodHRwczovL2phbnMuaW8vb2F1dGgvY29uZmlnL2p3a3MucmVhZG9ubHkiLCJodHRwczovL2phbnMuaW8vb2F1dGgvY29uZmlnL2ZpZG8yLnJlYWRvbmx5IiwiaHR0cHM6Ly9qYW5zLmlvL29hdXRoL2NvbmZpZy9jYWNoZS5yZWFkb25seSIsImh0dHBzOi8vamFucy5pby9vYXV0aC9qYW5zLWF1dGgtc2VydmVyL2NvbmZpZy9wcm9wZXJ0aWVzLnJlYWRvbmx5IiwiaHR0cHM6Ly9qYW5zLmlvL29hdXRoL2NvbmZpZy9kYXRhYmFzZS9jb3VjaGJhc2UucmVhZG9ubHkiXSwiaXNzIjoiaHR0cHM6Ly9jZS1kZXY2LmdsdXUub3JnIiwidG9rZW5fdHlwZSI6ImJlYXJlciIsImV4cCI6MTYxMzczNjk2NCwiaWF0IjoxNjEzNzM2NjY0LCJjbGllbnRfaWQiOiJiNmNjOWFkYS1jYTBhLTQyOTQtOWJiZS0yMmNjZWQyOWU5MjEifQ.h0V_werNJv4KD79ZpMen_KI6Cj44qodqmnrRkirnw6VVmY5WoSTA4ER8GIwARWUYhf8551ADI-ldkh0RTSd3PiATskdjmY8tfH3V7zDvMH2N6jq9yXAmnrhXT1QE7jAGfqtDQZzdcVAa2FumLbsENQvEXCAaVf52i0UMmAy0ytjsSWH1J8HBbcBeQ84pTgUNT09g0osuywyEcJejWPnfYCHVV8uj0cu9yiKpTVGphaKEy1LmQsPJq1UrtmeyqMc81e7jGM-51wJh17jEk8Iy1DvlwD5iOrrt2a7j2DyamWhOWhxrGNsLJljSBzSz_O4En5nkqUhTgsUURYt3nCzy6Q' 
	And param limit = 3 
	When method GET 
	Then status 200
	And print response 
	And assert response.length == 3 

@ignore
Scenario: Search attributes given a search pattern 
	Given url mainUrl
	And header Authorization = 'Bearer ' + accessToken 
	And param pattern = 'city' 
	When method GET 
	Then status 200
	And print response 
	And assert response.length == 1 

@ignore
Scenario: Fetch the first three active attributes 
	Given url mainUrl
	And header Authorization = 'Bearer ' + accessToken 
	And param limit = 3 
	And param status = 'active' 
	When method GET 
	Then status 200
	And print response 
	And assert response.length == 3 
	And assert response[0].status == 'ACTIVE'
	And assert response[1].status == 'ACTIVE'
	And assert response[2].status == 'ACTIVE'	

@ignore
Scenario: Fetch the first three inactive attributes 
	Given url mainUrl
	And header Authorization = 'Bearer ' + accessToken 
	And param limit = 3 
	And param status = 'inactive' 
	When method GET 
	Then status 200
	And print response 
	And assert response.length == 3 
	And assert response[0].status == 'INACTIVE'
	And assert response[1].status == 'INACTIVE'
	And assert response[2].status == 'INACTIVE'		

@ignore
@CreateUpdateDelete 
Scenario: Create new attribute 
	Given url mainUrl
	And header Authorization = 'Bearer ' + accessToken 
	And request read('attribute.json') 
	When method POST 
	Then status 201 
	Then def result = response 
	Then set result.displayName = 'UpdatedQAAddedAttribute' 
	Then def inum_before = result.inum 
	Given url mainUrl
	And header Authorization = 'Bearer ' + accessToken 
	And request result 
	When method PUT 
	Then status 200 
	And assert response.displayName == 'UpdatedQAAddedAttribute' 
	And assert response.inum == inum_before 
	Given url mainUrl + '/' +response.inum
	And header Authorization = 'Bearer ' + accessToken 
	When method DELETE 
	Then status 204 

@ignore
Scenario: Delete a non-existion attribute by inum 
	Given url mainUrl + '/1402.66633-8675-473e-a749'
	And header Authorization = 'Bearer ' + accessToken 
	When method GET 
	Then status 404 
	
@ignore
Scenario: Get an attribute by inum(unexisting attribute) 
	Given url mainUrl + '/53553532727272772'
	And header Authorization = 'Bearer ' + accessToken 
	When method GET 
	Then status 404 

@ignore
Scenario: Get an attribute by inum 
	Given url mainUrl
	And header Authorization = 'Bearer ' + accessToken 
	When method GET 
	Then status 200 
	Given url mainUrl + '/' +response[0].inum
	And header Authorization = 'Bearer ' + accessToken
	When method GET 
	Then status 200
	And print response
	