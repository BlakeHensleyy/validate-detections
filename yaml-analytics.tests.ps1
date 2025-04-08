# Validation for PascalCase (GreaterThan)
$script:regEx_PascalCase = "^[A-Z][a-z]+(?:[A-Z][a-z]+)*$"

# Validation for camelCase (scheduledRule)
$script:regEx_camelCase = "^[a-z]+(?:[A-Z][a-z]+)*$"

# Validation for camelCase (scheduledRule)
$script:regEx_lowerCase = "^[a-z]*$"

# Validation for valid GUID value (00000000-ffff-bbbb-aaaa-000000000000)
$script:regEx_Guid = '^[{]?[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}[}]?$'

# Validation for value between 0 and 10000
$script:regEx_MaxValue = '^([0-9]|[1-9][0-9]|[1-9][0-9][0-9]|[1-9][0-9][0-9][0-9]|10000)$'

# Validation for Mitre Technique with subvalue (T1078) or (T1078.001)
$script:regEx_Technique = '^(([T0-9]{5}))+(?:[.0-9]{4})?$'

# Validation for version number (1.3.1)
$script:regEx_Version = '^([0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,2})$'

# Validation for duration with max values of P14D (14 days), PT24H (24 hours) PT1440M (1440 minutes)
$script:regEx_yamlTime = '^[1-9]d|^1[0-4]d|([1-9]|[1-9][0-9]|[1-2][0-9][0-9]|3[0-3][0-6])h|([5-9]|[1-9][0-9]|[1-9][0-9][0-9]|1[0-3][0-9][0-9]|14[0-3][0-9]|1440)m'

Describe "Detections" {

    $testCases = Get-ChildItem -Path $detectionsPath -Include "*.yaml", "*.yml" -Exclude "action.yml", "*pipelines.yml", "*variables.yml" -Recurse | ForEach-Object -Process {
        @{
            file       = $_.FullName
            yamlObject = (Get-Content -Path $_.FullName | ConvertFrom-Yaml)
            path       = $_.DirectoryName
            name       = $_.Name
        }
    }

    Context "General" {

        It 'Converts from YAML | <Name>' -TestCases $testCases {
            param ($file, $yamlObject)
            $yamlObject | Should -Not -BeNullOrEmpty
        }
    }
    
    Context "Properties" {

        It 'Do properties use camelCasing | <Name>' -TestCases $testCases {
            param ($file,$yamlObject)
            ($yamlObject.psobject.Properties | Where-Object Name -eq Keys).value.ForEach{
                $_ | Should -MatchExactly $regEx_camelCase
            }
        }

        It 'Kind should be in the allowed list | <Name>' -TestCases $testCases {
            param ($file,$yamlObject)

            $kind = $yamlObject.kind
            $expectedKind = @(
                'Scheduled',
                'NRT'
            )

            $kind | Should -BeIn $expectedKind
        }

        It 'Version should not be empty | <Name>' -TestCases $testCases {
            param ($file,$yamlObject)

            $version = $yamlObject.version
            $version | Should -Not -BeNullOrEmpty
        }

        It 'Name should not be empty | <Name>' -TestCases $testCases {
            param ($file,$yamlObject)

            $name = $yamlObject.name
            $name | Should -Not -BeNullOrEmpty
        }

        It 'Description should not be empty | <Name>' -TestCases $testCases {
            param ($file,$yamlObject)

            $description = $yamlObject.description
            $description | Should -Not -BeNullOrEmpty
        }

        It 'Version should be in a valid format | <Name>' -TestCases $testCases {
            param ($file,$yamlObject)

            $version = $yamlObject.version
            $version | Should -MatchExactly $regEx_Version
        }

        It 'Severity should be in the allowed list | <Name>' -TestCases $testCases {
            param ($file,$yamlObject)

            $severities = $yamlObject.severity
            $expectedSeverity = @(
                'Low',
                'Medium',
                'High',
                'Informational'
            )
            foreach ($severity in $severities) {
                $severity | Should -BeIn $expectedSeverity
            }
        }

        It 'Severity should be in PascalCase | <Name>' -TestCases $testCases {
            param ($file,$yamlObject)
            $yamlObject.severity | Should -MatchExactly $regEx_PascalCase
        }

        It 'Trigger should be in the allowed list values | <Name>' -TestCases $testCases {
            param ($file,$yamlObject)

            $expectedOperator = @(
                'eq',
                'gt',
                'lt',
                'ne'
            )
            if ($yamlObject.kind -eq 'Scheduled') {
                $yamlObject.triggerOperator | Should -BeIn $expectedOperator
            }
        }

        It 'TriggerOperator value should be in LowerCase | <Name>' -TestCases $testCases {
            param ($file,$yamlObject)
            if ($yamlObject.kind -eq 'Scheduled') {
                $yamlObject.TriggerOperator | Should -MatchExactly $regEx_LowerCase
            }
        }

        It 'Threshold should be a integer value | <Name>' -TestCases $testCases {
            param ($file,$yamlObject)
            if ($yamlObject.kind -eq 'Scheduled') {
                $yamlObject.triggerThreshold | Should -BeOfType System.ValueType
            }
        }

        It 'Threshold should not be more than 10000 | <Name>' -TestCases $testCases {
            param ($file,$yamlObject)

            if ($yamlObject.kind -eq 'Scheduled') {
                $yamlObject.triggerThreshold | Should -MatchExactly $regEx_MaxValue
            }
        }

# ~~~~~~~~~~~~~~ ALL MITRE ATTACK TACTICS AND TECHNIQUE CHECKS ARE COMMENTED OUT UNTIL THE QUALITY OF ANALYTIC RULES ARE IMPROVED. TOO MANY FAILS. ~~~~~~~~~~~~~~~~~~~

#        It 'Tactics should be in the expected value list | <Name>' -TestCases $testCases {
#            param ($file,$yamlObject)
#
#            # The Tactics are updated from the azure-sentinel repo if faulty error occurs: https://github.com/Azure/Azure-Sentinel/blob/master/.script/tests/detectionTemplateSchemaValidation/Models/AttackTactic.cs
#            $expectedTactics = @(
#                'Collection',
#                'CommandAndControl',
#                'CredentialAccess',
#                'DefenseEvasion',
#                'Discovery',
#                'Exfiltration',
#                'Execution',
#                'Impact',
#                'ImpairProcessControl',
#                'InitialAccess',
#                'InhibitResponseFunction',
#                'LateralMovement',
#                'Persistence',
#                'PreAttack',
#                'PrivilegeEscalation',
#                'Reconnaissance',
#                'ResourceDevelopment'
#            )
#            foreach ($tactic in $yamlObject.tactics) {
#                $tactic | Should -BeIn $expectedTactics
#            }
#        }
#

#        It 'Tactics should be in PascalCase | <Name>' -TestCases $testCases {
#            param ($file,$yamlObject)
#            $tactics = $yamlObject.tactics
#
#            foreach ($tactic in $tactics) {
#                $tactic | Should -MatchExactly $regEx_PascalCase
#            }
#        }

#        It 'Technique should be not be empty | <Name>' -TestCases $testCases {
#            param ($file,$yamlObject)
#            $techniques = $yamlObject.relevantTechniques
#            $techniques.count | Should -BeGreaterOrEqual 1
#
#        }

#        It 'Technique should start with T followed by 4 numbers | <Name>' -TestCases $testCases {
#            param ($file,$yamlObject)
#            $techniques = $yamlObject.relevantTechniques
#
#            foreach ($technique in $techniques) {
#                $technique | Should -MatchExactly $regEx_Technique
#            }
#        }

        It 'The id should be a valid GUID | <Name>' -TestCases $testCases {
            param ($file,$yamlObject)
            $id = $yamlObject.id
            $id | Should -MatchExactly $regEx_Guid
        }

        It 'Entity Type should be in the expected value list and have valid identifiers | <Name>' -TestCases $testCases {
            param ($file, $yamlObject)

            # The entities are populated following this file. Update with any changes to it to fix issues: https://github.com/Azure/Azure-Sentinel/blob/master/.script/tests/detectionTemplateSchemaValidation/Models/EntityMappingIdentifiers.cs
            $expectedEntityTypes = @(
                'Account',
                'AzureResource',
                'CloudApplication',
                'DNS',
                'File',
                'FileHash',
                'Host',
                'IP',
                'IoTDevice',
                'Mailbox',
                'MailCluster',
                'MailMessage',
                'Malware',
                'Process',
                'RegistryKey',
                'RegistryValue',
                'SecurityGroup',
                'SentinelEntities',
                'SubmissionMail',
                'URL'
            )

            $entityIdentifiersMap = @{
                'Account' = @("Name", "FullName", "NTDomain", "DnsDomain", "UPNSuffix", "Sid", "AadTenantId", "AadUserId", "PUID", "IsDomainJoined", "DisplayName", "ObjectGuid","CloudAppAccountId")
                'AzureResource' = @("ResourceId")
                'CloudApplication' = @("AppId", "Name", "InstanceName")
                'DNS' = @("DomainName")
                'File' = @("Directory", "Name")
                'FileHash' = @("Algorithm", "Value")
                'Host' = @("DnsDomain", "NTDomain", "HostName", "FullName", "NetBiosName", "AzureID", "OMSAgentID", "OSFamily", "OSVersion", "IsDomainJoined")
                'IoTDevice' = @("DeviceId", "DeviceName", "Manufacturer", "Model", "FirmwareVersion", "OperatingSystem", "MacAddress", "Protocols", "SerialNumber", "Source", "IoTSecurityAgentId", "DeviceType")
                'IP' = @("Address")
                'Mailbox' = @("MailboxPrimaryAddress", "DisplayName", "Upn", "ExternalDirectoryObjectId", "RiskLevel")
                'MailCluster' = @("NetworkMessageIds", "CountByDeliveryStatus", "CountByThreatType", "CountByProtectionStatus", "Threats", "Query", "QueryTime", "MailCount", "IsVolumeAnomaly", "Source", "ClusterSourceIdentifier", "ClusterSourceType", "ClusterQueryStartTime", "ClusterQueryEndTime", "ClusterGroup")
                'MailMessage' = @("Recipient", "Urls", "Threats", "Sender", "P1Sender", "P1SenderDisplayName", "P1SenderDomain", "SenderIP", "P2Sender", "P2SenderDisplayName", "P2SenderDomain", "ReceivedDate", "NetworkMessageId", "InternetMessageId", "Subject", "BodyFingerprintBin1", "BodyFingerprintBin2", "BodyFingerprintBin3", "BodyFingerprintBin4", "BodyFingerprintBin5", "AntispamDirection", "DeliveryAction", "DeliveryLocation", "Language", "ThreatDetectionMethods")
                'Malware' = @("Name", "Category")
                'Process' = @("ProcessId", "CommandLine", "ElevationToken", "CreationTimeUtc")
                'RegistryKey' = @("Hive", "Key")
                'RegistryValue' = @("Name", "Value", "ValueType")
                'SecurityGroup' = @("DistinguishedName", "SID", "ObjectGuid")
                'SubmissionMail' = @("NetworkMessageId", "Timestamp", "Recipient", "Sender", "SenderIp", "Subject", "ReportType", "SubmissionId", "SubmissionDate", "Submitter")
                'URL' = @("Url")
            }
        
            foreach ($entityMapping in $yamlObject.entityMappings) {
                $entityType = $entityMapping.entityType
                $entityType | Should -BeIn $expectedEntityTypes
        
                foreach ($fieldMapping in $entityMapping.fieldMappings) {
                    $identifier = $fieldMapping.identifier
                    $validIdentifiers = $entityIdentifiersMap[$entityType]
                    $identifier | Should -BeIn $validIdentifiers
                }
            }
        }

        It 'Entity Type should be in PascalCase | <Name>' -TestCases $testCases {
            param ($file,$yamlObject)
            $entityTypes = $yamlObject.entityMappings.entityType

            foreach ($entityType in $entityTypes) {
                if ($entityType -notlike "*IP*" -and $entityType -notlike "*URL*" -and $entityType -notlike "*DNS*") {
                    $entityType | Should -MatchExactly $regEx_PascalCase
                }
            }
        }

        It 'Entity IP, URL and DNS should be in Capitals | <Name>' -TestCases $testCases {
            param ($file,$yamlObject)
            $entityTypes = $yamlObject.entityMappings.entityType

            foreach ($entityType in $entityTypes) {
                if ($entityType -eq "IP" -or $entityType -eq "URL" -or $entityType -eq "DNS") {
                    $entityType | Should -MatchExactly '^[A-Z]+(?:[A-Z]+)*$'
                }
            }
        }

        It 'Query Frequency should be a valid format | <Name>' -TestCases $testCases {
            param ($file,$yamlObject)

            if ($yamlObject.kind -eq 'Scheduled') {
                $yamlObject.queryFrequency | Should -MatchExactly $regEx_yamlTime
            }
        }

        It 'Query Period should be a valid format | <Name>' -TestCases $testCases {
            param ($file,$yamlObject)

            if ($yamlObject.kind -eq 'Scheduled') {
                $yamlObject.queryPeriod | Should -MatchExactly $regEx_yamlTime
            }
        }

        It 'Query Frequency should be less or equal than Query Period | <Name>' -TestCases $testCases {
            param (
                $file,
                $yamlObject
            )

            function Convert-Time($value) {
                switch -wildcard ($value) {
                    "*d*" {
                        $result = New-TimeSpan -Days $value.replace('d', '')
                    }
                    "*h*" {
                        $result = New-TimeSpan -Hours $value.replace('h', '')
                    }
                    "*m*" {
                        $result = New-TimeSpan -Minutes $value.replace('m', '')
                    }
                    Default {}
                }
                return $result
            }

            if ($yamlObject.kind -eq 'Scheduled') {
                $queryFrequency = Convert-Time -value "$($yamlObject.queryFrequency)"
                $queryPeriod = Convert-Time -value "$($yamlObject.queryPeriod)"

                $queryFrequency.TotalMinutes | Should -BeLessOrEqual $queryPeriod.TotalMinutes
            }
        }

        It 'Query Frequency should be more than 60 minutes when Period is greater or equal than 2 days | <Name>' -TestCases $testCases {
            param (
                $file,
                $yamlObject
            )

            function Convert-Time($value) {
                switch -wildcard ($value) {
                    "*d*" {
                        $result = New-TimeSpan -Days $value.replace('d', '')
                    }
                    "*h*" {
                        $result = New-TimeSpan -Hours $value.replace('h', '')
                    }
                    "*m*" {
                        $result = New-TimeSpan -Minutes $value.replace('m', '')
                    }
                    Default {}
                }
                return $result
            }

            if ($yamlObject.kind -eq 'Scheduled') {
                $queryFrequency = Convert-Time -value "$($yamlObject.queryFrequency)"
                $queryPeriod = Convert-Time -value "$($yamlObject.queryPeriod)"

                if ($queryPeriod.TotalDays -ge 2) {
                    $queryFrequency.TotalMinutes | Should -BeGreaterThan 59
                }
            }
        }
    }
}
