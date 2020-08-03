Feature: Openid connect clients

Scenario: Fetch all openid connect scopes without bearer token
Given url openidscopes_url
When method GET
Then status 401

Scenario: Fetch all openid connect scopes
Given url openidscopes_url
And  header Authorization = 'Bearer ' + accessToken
When method GET
Then status 200
And assert response.length != null

Scenario: Fetch the first three openidconnect scopes
Given url openidscopes_url
And  header Authorization = 'Bearer ' + accessToken
And param limit = 3
When method GET
Then status 200
And assert response.length == 3

Scenario: Search openid connect scopes given a serach pattern
Given url openidscopes_url
And  header Authorization = 'Bearer ' + accessToken
And param pattern = 'openid'
When method GET
Then status 200
And assert response.length == 1

@CreateUpdateDelete
Scenario: Create new OpenId Connect Scope
#Given url openidscopes_url
#And header Authorization = 'Bearer ' + accessToken
#And request read('classpath:add_scope.json')
#When method POST
#Then status 201
#Then def result = response
#Then set result.displayName = 'UpdatedQAAdddedScope'
Given url openidscopes_url
And header Authorization = 'Bearer ' + accessToken
And request result
When method PUT
Then status 200
And assert response.displayName == 'UpdatedQAAdddedScope'
Given url openidscopes_url + '/' +response.inum
And header Authorization = 'Bearer ' + accessToken
When method DELETE
Then status 204

Scenario: Delete a non-existion openid connect scope by inum
Given url openidscopes_url + '/1402.66633-8675-473e-a749'
And header Authorization = 'Bearer ' + accessToken
When method GET
Then status 404