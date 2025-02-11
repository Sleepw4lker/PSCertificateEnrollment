function Invoke-AutoEnrollmentTask {

    [CmdletBinding()]
    param(
        [Alias("Machine")]
        [Parameter(Mandatory=$False)]
        [Switch]
        $MachineContext = $False,

        [Parameter(Mandatory=$false)]
        [switch]
        $Wait
    )

    begin {}

    process {

        # Ensuring we work with Elevation when messing with the Computer Certificate Store
        If ($MachineContext.IsPresent) {
    
            If (-not (
                [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
                ).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
                Write-Error -Message "This must be run with Elevation (Run as Administrator) when using the Machine Context!" 
                return
            }
        }

        If ($MachineContext.IsPresent) {
            $TaskName = "SystemTask"
            $Flags = $TaskRunFlags.TASK_RUN_NO_FLAGS
        }
        Else {
            $TaskName = "UserTask"
            $Flags = $TaskRunFlags.TASK_RUN_AS_SELF # The task is run as the user who is calling the Run method (instead of "INTERACTIVE")
        }

        Try {

            $TaskScheduler = New-Object -ComObject "Schedule.Service"
            $TaskScheduler.Connect()

            $UserTask = $TaskScheduler.GetFolder("Microsoft\Windows\CertificateServicesClient").GetTask($TaskName)

            # https://docs.microsoft.com/en-us/windows/win32/taskschd/registeredtask-runex
            [void]($UserTask.RunEx($null, $Flags, 0, $null))

            if ($Wait.IsPresent) {
                do {
                    Start-Sleep -Seconds 1
                } while ((Get-ScheduledTask -TaskPath \Microsoft\Windows\CertificateServicesClient\ -TaskName $TaskName).PSBase.CimInstanceProperties['State'].Value -eq [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.StateEnum]::Running)
            }

            return $True

        }
        Catch {
            Write-Error -Message $PSItem.Exception.Message
            return
        }
        Finally {
            [void]([System.Runtime.Interopservices.Marshal]::ReleaseComObject($UserTask))
            [void]([System.Runtime.Interopservices.Marshal]::ReleaseComObject($TaskScheduler))
        }
    }

    end {}
    
}