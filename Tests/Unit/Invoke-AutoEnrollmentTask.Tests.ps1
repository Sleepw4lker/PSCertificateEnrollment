BeforeAll {
    Import-Module "$PSScriptRoot\..\..\PSCertificateEnrollment.psd1" -Force

    # Stand-in for the Schedule.Service COM object: records which task was run how. No task is
    # ever started.
    function New-FakeTaskScheduler {
        param([string] $GetTaskError)

        $Task = [PSCustomObject]@{ RunFlags = $null }
        $Task | Add-Member -MemberType ScriptMethod -Name RunEx -Value {
            param($Params, $Flags, $SessionId, $User)
            $this.RunFlags = $Flags
        }

        $Folder = [PSCustomObject]@{ Task = $Task; TaskName = $null; GetTaskError = $GetTaskError }
        $Folder | Add-Member -MemberType ScriptMethod -Name GetTask -Value {
            param($Name)
            if ($this.GetTaskError) { throw $this.GetTaskError }
            $this.TaskName = $Name
            $this.Task
        }

        $Scheduler = [PSCustomObject]@{ Folder = $Folder; FolderPath = $null }
        $Scheduler | Add-Member -MemberType ScriptMethod -Name Connect -Value {}
        $Scheduler | Add-Member -MemberType ScriptMethod -Name GetFolder -Value {
            param($Path)
            $this.FolderPath = $Path
            $this.Folder
        }
        $Scheduler
    }

    # A client-side stand-in for the task as Get-ScheduledTask returns it (State: 3 = Ready, 4 = Running)
    function New-ScheduledTaskState {
        param([uint32] $State)
        New-CimInstance -ClassName MSFT_ScheduledTask -Namespace Root/Microsoft/Windows/TaskScheduler -ClientOnly -Property @{ State = $State }
    }
}

AfterAll {
    Remove-Module -Name PSCertificateEnrollment -Force -ErrorAction SilentlyContinue
}

Describe 'Invoke-AutoEnrollmentTask' {

    BeforeEach {
        $Script:Scheduler = New-FakeTaskScheduler
        Mock New-Object -ModuleName PSCertificateEnrollment -ParameterFilter { $ComObject -eq 'Schedule.Service' } { $Script:Scheduler }
        # The fakes are no COM objects, so they cannot go through the real release
        Mock Unregister-ComObject -ModuleName PSCertificateEnrollment -RemoveParameterType ComObject {}
        Mock Start-Sleep -ModuleName PSCertificateEnrollment {}
    }

    It 'runs the user task as the calling user' {
        Invoke-AutoEnrollmentTask | Should -BeTrue

        $Script:Scheduler.FolderPath | Should -Be 'Microsoft\Windows\CertificateServicesClient'
        $Script:Scheduler.Folder.TaskName | Should -Be 'UserTask'
        $Script:Scheduler.Folder.Task.RunFlags | Should -Be 1 # TASK_RUN_AS_SELF
    }

    It 'runs the system task for -MachineContext when elevated' {
        Mock Test-IsElevated -ModuleName PSCertificateEnrollment { $true }

        Invoke-AutoEnrollmentTask -MachineContext | Should -BeTrue

        $Script:Scheduler.Folder.TaskName | Should -Be 'SystemTask'
        $Script:Scheduler.Folder.Task.RunFlags | Should -Be 0 # TASK_RUN_NO_FLAGS
    }

    It 'refuses -MachineContext without elevation' {
        Mock Test-IsElevated -ModuleName PSCertificateEnrollment { $false }

        { Invoke-AutoEnrollmentTask -MachineContext -ErrorAction Stop } | Should -Throw '*Elevation*'
        Should -Invoke New-Object -ModuleName PSCertificateEnrollment -Times 0 -Exactly -ParameterFilter { $ComObject -eq 'Schedule.Service' }
    }

    It 'waits for the task to finish with -Wait' {
        $Script:Polls = 0
        Mock Get-ScheduledTask -ModuleName PSCertificateEnrollment {
            $Script:Polls++
            if ($Script:Polls -lt 3) { New-ScheduledTaskState -State 4 } else { New-ScheduledTaskState -State 3 }
        }

        Invoke-AutoEnrollmentTask -Wait | Should -BeTrue

        Should -Invoke Get-ScheduledTask -ModuleName PSCertificateEnrollment -Times 3 -Exactly -ParameterFilter {
            $TaskPath -eq '\Microsoft\Windows\CertificateServicesClient\' -and $TaskName -eq 'UserTask'
        }
    }

    It 'reports why the task could not be started' {
        $Script:Scheduler = New-FakeTaskScheduler -GetTaskError 'The system cannot find the file specified.'

        { Invoke-AutoEnrollmentTask -ErrorAction Stop } | Should -Throw '*cannot find the file specified*'
    }

    It 'releases the scheduler and the task' {
        $null = Invoke-AutoEnrollmentTask

        Should -Invoke Unregister-ComObject -ModuleName PSCertificateEnrollment -Times 2 -Exactly
    }
}
