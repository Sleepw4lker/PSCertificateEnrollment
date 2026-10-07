BeforeAll {
    Import-Module "$PSScriptRoot\..\..\PSCertificateEnrollment.psd1" -Force
}

AfterAll {
    Remove-Module -Name PSCertificateEnrollment -Force -ErrorAction SilentlyContinue
}

Describe 'Unregister-ComObject' {

    It 'releases a COM object so it can no longer be used' {
        InModuleScope PSCertificateEnrollment {
            $ObjectId = New-Object -ComObject X509Enrollment.CObjectId
            $ObjectId.InitializeFromValue('1.2.3')

            $ObjectId | Unregister-ComObject

            { $ObjectId.Value } | Should -Throw
        }
    }

    It 'releases every object passed through the pipeline' {
        InModuleScope PSCertificateEnrollment {
            $Objects = @(
                New-Object -ComObject X509Enrollment.CObjectId
                New-Object -ComObject X509Enrollment.CObjectId
            )

            $Objects | Unregister-ComObject

            $Objects | ForEach-Object { { $_.Value } | Should -Throw }
        }
    }

    It 'accepts $null without an error' {
        InModuleScope PSCertificateEnrollment {
            { $null | Unregister-ComObject -ErrorAction Stop } | Should -Not -Throw
        }
    }

    It 'rejects an object that is not a COM object' {
        InModuleScope PSCertificateEnrollment {
            { Unregister-ComObject -ComObject ([pscustomobject]@{}) } | Should -Throw -ErrorId 'ParameterArgumentTransformationError,Unregister-ComObject'
        }
    }
}
