# Intern Test API#
## Preposition ##
We have a lot of issues from vulnerable libs on our Linux boxes. 
We need a service that can generate a list from a database of package(library) versions, that have open vulnerabilities.
This way we'll know which versions we have to avoid.
## Requirements ##
### Languages ###
Please implement this in Python or Java. Preferably Python with fastapi framework. 
### Access Point ###
We're going to need a rest API to be served by this app. 
#### Request format ####
We would like to be able to send GET requests to this service (the one you have to create) as shown in the example.
`http://127.0.0.1:80/versions?name=xz-utils`
#### Response format ####
Response should be a JSON object with the following values:
- name: name of the package that is equal to the query param value
- versions: list of affected versions of the package
- timestamp: timestamp of the request

Example: 
`{
    "name": "xz-utils",
    "versions": [
        "5.2.2-1.3ubuntu0.1",
        "5.2.4-1ubuntu1.1",
        "5.1.1alpha+20120614-2ubuntu2.14.04.1+esm1",
        "5.1.1alpha+20120614-2ubuntu2.16.04.1+esm1"
    ],
    "timestamp": "2024-05-10 22:13:18"
}`

### Datasource ###
The service has to rely on the osv.dev database to check for vulnerabilities.
The following ecosystems should be used: 'Debian', 'Ubuntu'. 
We have to get the versions from both ecosystems aggregated in one list of one response. Possible duplications should be removed in the result list.

### Tests ###
There is no test coverage requirement for this service on this level. 

### Ambitionlevels ###
Most important: Do not worry if you can't do this all in time!

Try to split the story into smaller steps.
- A runnable (Python|Java) application
- Executing a API call to `https://api.osv.dev/v1/query` (If you can't, not problem just mock a json response) HINT: https://osv.dev/docs/osv_service_v1.swagger.json
- Parsing the given JSON and getting the list of versions aggregated
- Get the list of versions sorted (ascending alphanumericly)
- Filter the duplicates from the list
- Define rest API to serve the response
- Using less memory to collect the versions
- Paralelly fetch the version from different ecosystems

