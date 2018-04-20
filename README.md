# securityfilter
Library that contains the authentication filter.

## How to Add to the System
1) The appsettings.json must have a key to the folder that will hold the keys for all APIs.
```json
...
  "KeyFolder": "/var/keys/"
...
```
2)  Add the nugget config file to import the nugget package
```xml

<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <add key="securityfilter" value="Path/To/NuggetFile" />
  </packageSources>
</configuration>
```

3) Then you must import the Nuget Package of the Solution
```xml
...
  <PackageReference Include="lorien.securityfilter" Version="0.0.9" />
...
```

4) Config the Encript Service Provider and the Data Protection in the Startup.cs
```csharp
...
if (!String.IsNullOrEmpty (Configuration["KeyFolder"]))
                services.AddDataProtection ()
                .SetApplicationName ("Lorien")
                .PersistKeysToFileSystem (new DirectoryInfo (Configuration["KeyFolder"]));

...
services.AddTransient<IEncryptService, EncryptService> ();
...
```
5) Add the filter with the permission it requires
```csharp
...
[HttpGet]
[SecurityFilter("get_permissions")]
public ActionResult Get () {
...
```