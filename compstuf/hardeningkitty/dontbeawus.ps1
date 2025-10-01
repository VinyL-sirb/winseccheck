Import-Module .\new-hardeningkitty\HardeningKitty.psm1
Invoke-HardeningKitty -Mode HailMary -Log -Report -FileFindingList .\new-hardeningkitty\lists\finding_list_0x6d69636b_machine.csv -SkipMachineInformation -SkipRestorePoint
Invoke-HardeningKitty -Mode HailMary -Log -Report -FileFindingList .\new-hardeningkitty\lists\finding_list_0x6d69636b_user.csv -SkipMachineInformation -SkipRestorePoint 
Invoke-HardeningKitty -Mode HailMary -Log -Report -FileFindingList .\new-hardeningkitty\lists\finding_list_cis_microsoft_windows_10_enterprise_21h2_machine.csv -SkipMachineInformation -SkipRestorePoint 
Invoke-HardeningKitty -Mode HailMary -Log -Report -FileFindingList .\new-hardeningkitty\lists\finding_list_cis_microsoft_windows_10_enterprise_21h2_user.csv -SkipMachineInformation -SkipRestorePoint 
Invoke-HardeningKitty -Mode HailMary -Log -Report -FileFindingList .\new-hardeningkitty\lists\finding_list_dod_microsoft_windows_10_stig_v2r1_machine.csv -SkipMachineInformation -SkipRestorePoint
Invoke-HardeningKitty -Mode HailMary -Log -Report -FileFindingList .\new-hardeningkitty\lists\finding_list_dod_microsoft_windows_10_stig_v2r1_user.csv -SkipMachineInformation -SkipRestorePoint 
Invoke-HardeningKitty -Mode HailMary -Log -Report -FileFindingList .\new-hardeningkitty\lists\finding_list_dod_windows_defender_antivirus_stig_v2r1.csv -SkipMachineInformation -SkipRestorePoint 
Invoke-HardeningKitty -Mode HailMary -Log -Report -FileFindingList .\new-hardeningkitty\lists\finding_list_dod_windows_firewall_stig_v1r7.csv -SkipMachineInformation -SkipRestorePoint 