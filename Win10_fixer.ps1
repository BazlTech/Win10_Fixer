<##########      Win10 Unbloat PLUS      #########

.AUTHOR:  Steven Bazzell

.DATE:  02 May 2018

.DESCRIPTION:  This script will uninstall a lot of the unnecessary
                software and add-ons that come pre-installed with
                Windows 10.  See areas in the script below for commented
                areas you may wish to comment or uncomment.  This scripts
                will also set some settings for Windows and other default
                Windows apps based on best security practices.

.WARNING:  This script could remove OneDrive, Cortana, and the Windows
            store from your system!!

.NOTES:  Some of the packages are listed more than once in a different
        format in order to catch the package as different Windows
        updates may have changed their names slightly.

.ERRORS:  You might get some errors when attempting to remove some
            apps that are actually integrated with Windows.  Unfortunately,
            these apps may not uninstall.  Just ignore those errors.

#>

#######   Here are all of the possible options to run:   #######
<#
RemoveWinBloat -- this removes a lot of the apps and programs that come
                preinstalled with a new installation of Windows 10.  See the
                RemoveBloat section to add or remove comments for the apps
                listing for those you want to keep or remove.

RemoveXboxBloat -- This removes the Xbox app and game manager

RemoveOneDrive -- This uninstalls OneDrive and removes it from Explorer Window

RemoveCortana -- This will remove that annoying Cortana assistant without
                  breaking your search feature

Remove_NewsIntersts -- This adjusts some settings to attempt to remove the News
                and interests included with some of the latest Win10 updates.
                Unfortunately, recent updates have made it very difficult for 
                this script to work.  You may still have to turn it off manually,
                but this script will set some other registry entries to help lessen
                the effect this package has on Windows performance.

Harden_SSL -- This sets all of the appropriate settings for SSL/TLS
                secure communication according to DISA STIGS

ClearDefaultStartMenu -- This clears out the start menu for accounts
                        created AFTER this is run.

#>


# First, tell Windows this script must be run with Administrator credentials
#Requires -RunAsAdministrator

############################################################
############    Remove Windows Bloatware     ############
############################################################

Function RemoveWinBloat {

    # List all of the bloatware packages
    # Comment any selections out you wish to Keep
    # Uncomment any selections you wish to remove
    $winbloatware = @(
        #"Microsoft.3DBuilder"
        "Microsoft.Appconnector"
        "Microsoft.BingFinance"
        "Microsoft.BingNews"
        "Microsoft.BingSports"
        "Microsoft.BingWeather"
        #"Microsoft.FreshPaint"
        "Microsoft.Getstarted"
        "Microsoft.MicrosoftOfficeHub"
        "Microsoft.MicrosoftSolitaireCollection"
        #"Microsoft.MicrosoftStickyNotes"
        "Microsoft.Office.OneNote"
        #"Microsoft.OneConnect"
        "Microsoft.People"
        "Microsoft.SkypeApp"
        #"Microsoft.Windows.Photos"
        "Microsoft.WindowsAlarms"
        #"Microsoft.WindowsCalculator"
        "Microsoft.WindowsCamera"
        "Microsoft.WindowsMaps"
        "Microsoft.WindowsPhone"
        "Microsoft.WindowsSoundRecorder"
        #"Microsoft.WindowsStore"
        "Microsoft.ZuneMusic"
        "Microsoft.ZuneVideo"
        "microsoft.windowscommunicationsapps"
        "Microsoft.MinecraftUWP"
        "Microsoft.MicrosoftPowerBIForWindows"
        "Microsoft.NetworkSpeedTest"
        "Microsoft.CommsPhone"
        "Microsoft.ConnectivityStore"
        "Microsoft.Messaging"
        "Microsoft.Office.Sway"
        "Microsoft.OneConnect"
        "Microsoft.WindowsFeedbackHub"
        "Microsoft.BingFoodAndDrink"
        "Microsoft.BingTravel"
        "Microsoft.BingHealthAndFitness"
        "Microsoft.WindowsReadingList"
        "*Microsoft.ScreenSketch*"
        "*828B5831.*"
        "*9E2F88E3.Twitter"
        "*PandoraMediaInc.29680B314EFC2"
        "Flipboard.Flipboard"
        "ShazamEntertainmentLtd.Shazam"
        "king.com.CandyCrushSaga"
        "king.com.CandyCrushSodaSaga"
        "*king.com.*"
        "*ClearChannelRadioDigital.iHeartRadio"
        "4DF9E0F8.Netflix"
        "6Wunderkinder.Wunderlist"
        "Drawboard.DrawboardPDF"
        "2FE3CB00.PicsArt-PhotoStudio"
        "D52A8D61.FarmVille2CountryEscape"
        "TuneIn.TuneInRadio"
        "GAMELOFTSA.Asphalt8Airborne"
        "TheNewYorkTimes.NYTCrossword"
        "DB6EA5DB.CyberLinkMediaSuiteEssentials"
        "*Facebook.*"
        "*flaregamesGmbH*"
        "*Nordcurrent*"
        "Playtika.CaesarsSlotsFreeCasino"
        "A278AB0D.MarchofEmpires"
        "KeeperSecurityInc.Keeper"
        "*ThumbmunkeysLtd.PhototasticCollage*"
        "XINGAG.XING"
        "89006A2E.AutodeskSketchBook"
        "D5EA27B7.Duolingo-LearnLanguagesforFree"
        "46928bounde.EclipseManager"
        "ActiproSoftwareLLC.562882FEEB491"
        "DolbyLaboratories.DolbyAccess"
        "SpotifyAB.SpotifyMusic"
        "A278AB0D.DisneyMagicKingdoms"
        "*WinZipComputing.WinZipUniversal"
        "*windowsalarm*"
        "*windowscommunication*"
        "*windowscamera*"
        "*officehub*"
        "*skypeapp*"
        "*getstarted*"
        "*zunemusic*"
        "*windowsmaps*"
        "*solitairecollection*"
        "*bingfinance*"
        "*zunevideo*"
        "*bingnews*"
        "*onenote*"
        #"*people*"
        "*windowsphone*"
        "*bingsports*"
        "*soundrecorder*"
        "*bingweather*"
        "Nordcurrent.CookingFever"
        "A278AB0D.DragonManiaLegends"
        "828B5831.HiddenCityMysteryofShadows"
        "*LinkedInforWIndows*"
        "Microsoft.Whiteboard"
        "*netflix*"
        "*.Sketchable"
        "*.Twitter"
        "*Fitbit*"
        "*Skype*"
        "*ToDos*"
        "*OfficeHub*"
        "*Office.Sway*"
        "Microsoft.YourPhone"
        )

    foreach ($bloat in $winbloatware)
    {
        if (Get-AppxPackage -Name $bloat -AllUsers)
        {
            Write-Host "$bloat found.  Removing..."
            Get-AppxPackage $bloat -AllUsers | Remove-AppxPackage -ErrorAction SilentlyContinue
            Get-AppxProvisionedPackage -Online | ? DisplayName -Like $bloat | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
        }
        else
        {
            Write-Host "$bloat Not Found.  Either doesn't exist or already deleted."
        }
    }

    Write-Host ""
    Write-Host -ForegroundColor DarkYellow "------ All selected Windows bloatware removed. ------`n"

    # Now keep them from coming back
    New-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Cloud Content' -Force >> $NULL
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Cloud Content' -Name 'DisableWindowsConsumerFeatures' -Value 1 -PropertyType 'DWord' -Force >> $NULL -ErrorAction SilentlyContinue
    Write-Host "Registry entry written to prevent bloatware from coming back.`n"
    Write-Host -ForegroundColor Yellow "Windows Bloatware removed.`n"

    # End of RemoveBloatware function
}

############################################################
############    Remove XBOX App and Manager     ############
############################################################

Function RemoveXboxBloat {

    $xboxbloat = @(
        "Microsoft.XboxApp"
        "*xboxapp*"
        "*xbox*"
        )

    foreach ($xbloat in $xboxbloat)
    {
        if (Get-AppxPackage -Name $xbloat -AllUsers)
        {
            Write-Host "$xbloat found.  Removing..."
            Get-AppxPackage $xbloat -AllUsers | Remove-AppxPackage -ErrorAction SilentlyContinue
            Get-AppxProvisionedPackage -Online | ? DisplayName -Like $xbloat | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
        }
        else
        {
            Write-Host "$xbloat Not Found.  Either doesn't exist or already deleted."
        }
    }

    New-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\xbgm' -Name 'Start' -Value 4 -PropertyType 'DWord' -Force >> $NULL
    New-ItemProperty 'HKCU:\System\GameConfigStore\' -Name 'GameDVR_Enabled' -Value 0 -PropertyType 'DWord' -Force >> $NULL
    New-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR' -Name 'AppCaptureEnabled' -Value 0 -PropertyType 'Dword' -Force >> $NULL
    Write-Host "Registry entry made to prevent XBOX App from running."

    # Disable the Xbox services that could still be running
    Set-Service XboxNetApiSvc -StartupType Disabled
    Set-Service XblAuthManager -StartupType Disabled
    Set-Service XblGameSave -StartupType Disabled
    Set-Service XboxGipSvc -StartupType Disabled
    #Set-Service xbgm -StartupType Disabled
    Write-Host -ForegroundColor Yellow "Xbox services disabled.`n"

    #End of RemoveXboxBloat function
}

############################################################
###############       Remove OneDrive        ###############
############################################################

Function RemoveOneDrive
{
    Write-Host ""
    Write-Host -ForegroundColor DarkYellow "------ Getting rid of OneDrive ------"
    Write-Host ""
    # First check to see if it is already stopped or uninstalled.
    if (Get-Process -Name OneDrive -ErrorAction SilentlyContinue)
    {
        Write-Host "OneDrive.exe is still running.  Killing it..."
        taskkill /f /im OneDrive.exe
    }
    else
    {
        Write-Host "OneDrive.exe not found running."
    }

    Write-Host "Now let's uninstall it..."
    C:\Windows\SysWOW64\OneDriveSetup.exe /uninstall
    Write-Host "OneDrive disabled and uninstalled."
    Write-Host "Now, let's get rid of it from File Explorer."
    New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT >> $NULL
    $checkpath1 = 'HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}'
    $checkpath2 = 'HKCR:\WOW6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}'
    if (Test-Path -Path $checkpath1)
    {
        New-ItemProperty -Path 'HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}' -Name 'System.IsPinnedToNameSpaceTree' -Value 0 -PropertyType 'DWord' -Force >> $NULL
    }
    else
    {
        New-Item -Path 'HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}'
        New-ItemProperty -Path 'HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}' -Name 'System.IsPinnedToNameSpaceTree' -Value 0 -PropertyType 'DWord' -Force >> $NULL
    }

    If (Test-Path -Path $checkpath2)
    {
        New-ItemProperty -Path 'HKCR:\WOW6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}' -Name 'System.IsPinnedToNameSpaceTree' -Value 0 -PropertyType 'DWord' -Force >> $NULL
    }
    else
    {
        New-Item -Path 'HKCR:\WOW6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}'
        New-ItemProperty -Path 'HKCR:\WOW6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}' -Name 'System.IsPinnedToNameSpaceTree' -Value 0 -PropertyType 'DWord' -Force >> $NULL
    }

    remove-psdrive -name HKCR
    New-Item 'HKLM:\Software\Policies\Microsoft\Windows\OneDrive' -Force >> $NULL
    New-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\OneDrive' -Name 'DisableFileSync' -Value 1 -PropertyType 'DWord' -Force >> $NULL
    New-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\OneDrive' -Name 'DisableFileSyncNGSC' -Value 1 -PropertyType 'DWord' -Force >> $NULL
    New-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\OneDrive' -Name 'DisableLibrariesDefaultSaveToOneDrive' -Value 1 -PropertyType 'DWord' -Force >> $NULL
    New-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\OneDrive' -Name 'PreventNetworkTrafficPreUserSignin' -Value 0 -PropertyType 'DWord' -Force >> $NULL
    Write-Host "OneDrive should no longer be visible in File Explorer."
    # Remove OneDrive from the start menu
    Write-Host "Removing OneDrive from the Start Menu."
    Remove-Item "$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" -Force -ErrorAction SilentlyContinue
    Write-Host "OneDrive removed from start menu."
    # Remove OneDrive from the startup apps
    # 0x30 Disables
    # 0x20 Enables
    Write-Host "Removing OneDrive from startup.`n"
    $checkpath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\'
    if (Test-Path -Path $checkpath)
    {
        New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run' -Name 'OneDrive' -Value ([byte[]](0x30,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)) -PropertyType Binary -Force >> $NULL
        New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run' -Name 'OneDriveSetup' -Value ([byte[]](0x30,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)) -PropertyType Binary -Force >> $NULL
    }
    else
    {
        New-Item 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run' -Force
        New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run' -Name 'OneDrive' -Value ([byte[]](0x30,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)) -PropertyType Binary -Force >> $NULL
        New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run' -Name 'OneDriveSetup' -Value ([byte[]](0x30,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)) -PropertyType Binary -Force >> $NULL
    }

    Write-Host -ForegroundColor Yellow "OneDrive Removed.`n"

    #End of RemoveOneDrive
}

##############################################################
##############         Remove  Cortana         ###############
##############################################################

Function RemoveCortana
{
    Write-Host ""
    Write-Host -ForegroundColor DarkYellow "------ Getting rid of Cortana ------"
    Write-Host ""
    New-Item 'HKLM:\Software\Policies\Microsoft\Windows\Windows Search' -Force >> $NULL
    # Disable Cortana
    New-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\Windows Search' -Name 'AllowCortana' -Value 0 -PropertyType 'DWord' -Force >> $NULL
    New-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaEnabled" -Value 0 -PropertyType "DWord" -Force >> $NULL
    New-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "CanCortanaBeEnabled" -Value 0 -PropertyType "DWord" -Force >> $NULL
    New-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Value 0 -PropertyType "DWord" -Force >> $NULL
    New-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "DeviceHistoryEnabled" -Value 0 -PropertyType "Dword" -Force >> $NULL
    New-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Value 0 -PropertyType "DWord" -Force >> $NULL
    New-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaInAmbientMode" -Value 0 -PropertyType "DWord" -Force >> $NULL

    # Disable Cortana on lock screen
    New-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\Windows Search' -Name 'AllowCOrtanaAboveLock' -Value 0 -PropertyType 'DWord' -Force >> $NULL

    # Disable web search from start menu
    New-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\Windows Search' -Name 'DisableWebSearch' -Value 1 -PropertyType 'DWord' -Force >> $NULL

    # Disable web results in search
    New-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\Windows Search' -Name 'ConnectedSearchUseWeb' -Value 0 -PropertyType 'DWord' -Force >> $NULL

    # Disable Voice Activation
    New-ItemProperty "HKCU:\Software\Microsoft\Speech_OneCOre\Preferences" -Name "VoiceActivationEnabledAboveLockScreen" -Value 0 -PropertyType "DWord" -Force >> $NULL

    # Disable Cortana search history
    New-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "HistoryEnabled" -Value 0 -PropertyType "DWord" -Force >> $NULL

    Write-Host -ForegroundColor Yellow "Cortana is disabled.`n"

    #End Remove Cortana Function
}

###############################################################
########     Harden Windows SSL and .NET settings     #########
###############################################################

Function Harden_SSL {
    Write-Host ""
    Write-Host "---------------------------- SSL Crypto Hardening ------------------------------"
    Write-Host ""
    Write-Host "Hardening your Server/Workstation with SSL/TLS Deployment IAW NIST SP 800-52 and Best Practices..."
    Write-Host ""
    Write-Host "--------------------------------------------------------------------------------"
    Write-Host ""

    # Disable Multi-Protocol Unified Hello
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello' -Force >> $NULL
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server' -Force >> $NULL
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client' -Force >> $NULL
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server' -name 'Enabled' -value 0 -PropertyType 'DWord' -Force >> $NULL
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server' -name 'DisabledByDefault' -Value 1 -PropertyType 'DWord' -Force >> $NULL
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client' -name 'Enabled' -value 0 -PropertyType 'DWord' -Force >> $NULL
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client' -name 'DisabledByDefault' -Value 1 -PropertyType 'DWord' -Force >> $NULL
    Write-Host "Multi-Protocol Unified Hello has been disabled."

    # Disable PCT 1.0
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server' -Force >> $NULL
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client' -Force >> $NULL
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server' -name 'Enabled' -value 0 -PropertyType 'DWord' -Force >> $NULL
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server' -Name 'DisabledByDefault' -Value 1 -PropertyType 'DWord' -Force >> $NULL
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client' -name 'Enabled' -value 0 -PropertyType 'DWord' -Force >> $NULL
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client' -Name 'DisabledByDefault' -Value 1 -PropertyType 'DWord' -Force >> $NULL
    Write-Host "PCT 1.0 protocol has been disabled. (PCI DSS requirements)"

    # Disable SSL 2.0 (PCI Compliance)
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0' -Force >> $NULL
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -Force >> $NULL
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -Force >> $NULL
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -name 'Enabled' -value 0 -PropertyType 'DWord' -Force >> $NULL
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -Name 'DisabledByDefault' -Value 1 -PropertyType 'DWord' -Force >> $NULL
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -name 'Enabled' -value 0 -PropertyType 'DWord' -Force >> $NULL
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -Name 'DisabledByDefault' -Value 1 -PropertyType 'DWord' -Force >> $NULL
    Write-Host "SSL 2.0 protocol has been disabled. (FUBAR)"

    # Disable SSL 3.0 (PCI Compliance) and enable "Poodle" protection
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0' -Force >> $NULL
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Force >> $NULL
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -Force >> $NULL
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -name 'Enabled' -value 0 -PropertyType 'DWord' -Force >> $NULL
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -name 'DisabledByDefault' -Value 1 -PropertyType 'DWord' -Force >> $NULL
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -name 'Enabled' -value 0 -PropertyType 'DWord' -Force >> $NULL
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -name 'DisabledByDefault' -Value 1 -PropertyType 'DWord' -Force >> $NULL
    Write-Host "SSL 3.0 protocol has been disabled. (POODLE)"

    # Disable TLS 1.0 for client and disable for server SCHANNEL communications
    # Suggested to disable TLS 1.0 entirely, but too many legacy applications still use TLS 1.0
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0' -Force >> $NULL
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Force >> $NULL
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Force >> $NULL
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -name 'Enabled' -value 0 -PropertyType 'DWord' -Force >> $NULL
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force >> $NULL
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -name 'Enabled' -value 0 -PropertyType 'DWord' -Force >> $NULL
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force >> $NULL
    Write-Host "TLS 1.0 protocol has been disabled for SERVER and CLIENT. (CRIME)"
    Write-Host -ForegroundColor Yellow "TLS 1.0 should be completey phased out by 30 June 2018 per PCI DSS 3.2"

    # Disable TLS 1.1 for client and server SCHANNEL communications
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1' -Force >> $NULL
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Force >> $NULL
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Force >> $NULL
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -name 'Enabled' -value 0 -PropertyType 'DWord' -Force >> $NULL
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force >> $NULL
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -name 'Enabled' -value 0 -PropertyType 'DWord' -Force >> $NULL
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force >> $NULL
    Write-Host "TLS 1.1 protocol has been enabled."

    # Add and Enable TLS 1.2 for client and server SCHANNEL communications
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Force >> $NULL
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Force >> $NULL
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -name 'Enabled' -value 1 -PropertyType 'DWord' -Force >> $NULL
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force >> $NULL
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -name 'Enabled' -value 1 -PropertyType 'DWord' -Force >> $NULL
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force >> $NULL
    Write-Host "TLS 1.2 protocol has been enabled."
    Write-Host ""

    # Add and Enable TLS 1.3 for client and server SCHANNEL communcations
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server' -Force >> $NULL
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client' -Force >> $NULL
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server' -name 'Enabled' -value 1 -PropertyType 'DWord' -Force >> $NULL
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server' -name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force >> $NULL
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client' -name 'Enabled' -value 1 -PropertyType 'DWord' -Force >> $NULL
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client' -name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force >> $NULL
    Write-Host "TLS 1.3 protocol has been enabled."
    Write-Host ""

    # Re-create the ciphers key.
    New-Item 'HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers' -Force >> $NULL

    # Disable weak & medium strength ciphers.
    $insecureCiphers = @(
      'DES 56/56',
      'NULL',
      'RC2 128/128',
      'RC2 40/128',
      'RC2 56/128',
      'RC2 64/128',
      'RC4 40/128',
      'RC4 56/128',
      'RC4 64/128',
      'RC4 128/128'
      'Triple DES 168/168'
    )
    Foreach ($insecureCipher in $insecureCiphers) {
      $key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey($insecureCipher)
      $key.SetValue('Enabled', 0, 'DWord')
      $key.close()
      Write-Host "Weak cipher $insecureCipher has been disabled."
    }

     Write-Host ""

    # Enable secure ciphers.
    $secureCiphers = @(
      'AES 128/128',
      'AES 256/256'
    )
    Foreach ($secureCipher in $secureCiphers) {
      $key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey($secureCipher)
      New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$secureCipher" -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force >> $NULL
      $key.close()
      Write-Host "Strong cipher $secureCipher has been enabled."
    }

     Write-Host ""

    # Disable MD5 hash.
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5' -Force >> $NULL
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5' -name 'Enabled' -value 0 -PropertyType 'DWord' -Force >> $NULL
    Write-Host "MD5 hash has been disabled."

    # Enable secure hashes
    # Enabling SHA -- some suggest this should be disabled, but doing so breaks TLS 1.0 communication completely.
    # ----------- ONLY DISABLE SHA IF NOT USING OR CONNECTING TO ANY RESOURCE THAT REQUIRES TLS 1.0 -----------------
    $secureHashes = @(
      'SHA',
      'SHA256',
      'SHA384',
      'SHA512'
    )

    Foreach ($secureHash in $secureHashes) {
      $key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes', $true).CreateSubKey($secureHash)
      New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\$secureHash" -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force >> $NULL
      $key.close()
      Write-Host "Hash $secureHash has been enabled."
    }
    Write-Host -ForegroundColor Yellow "Look at disabling SHA in the future when you no longer need TLS 1.0."
    Write-Host ""

    # Set KeyExchangeAlgorithms configuration.
    # Look at getting rid of Diffie-Hellman in the future when you no longer need TLS 1.0 for client or server
    New-Item 'HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms' -Force >> $NULL
    $secureKeyExchangeAlgorithms = @(
      'Diffie-Hellman',
      'ECDH',
      'PKCS'
    )
    Foreach ($secureKeyExchangeAlgorithm in $secureKeyExchangeAlgorithms) {
      $key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms', $true).CreateSubKey($secureKeyExchangeAlgorithm)
      New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\$secureKeyExchangeAlgorithm" -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force >> $NULL
      $key.close()
      Write-Host "KeyExchangeAlgorithm $secureKeyExchangeAlgorithm has been enabled."
    }

    # Disable RSA encryption
    # Disabling this breaks TLS 1.1 and TLS 1.2 for some reason
    #New-Item "HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS" -Force >> $NULL
    #New-ItemProperty "HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS" -Name "Enabled" -Value '0' -PropertyType 'DWord' -Force >> $NULL
    #Write-Host "Disabled RSA Key Exchange Algorithm. (ROBOT)"
    #Write-Host ""

    # Logjam Attack Mitigation
    # Set minimum client key bit length for Diffie-Hellman to 2048 bits
    # The decimal value 2048 converted to HEX is 0x0800
    # The max value for this setting is 4096 bits
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman' -Name 'ClientMinKeyBitLength' -Value '0x0800' -PropertyType 'DWord' -Force >> $NULL
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman' -Name 'ServerMinKeyBitLength' -Value '0x0800' -PropertyType 'DWord' -Force >> $NULL
    Write-Host "Diffie-Hellman minium key bit length set to 2048 bit. (Logjam)"
    Write-Host ""

    # Set cipher suites order as secure as possible (Enables Perfect Forward Secrecy).
    # Check for OS version and apply accordingly.
    $os = Get-WmiObject -class Win32_OperatingSystem
    if ([System.Version]$os.Version -lt [System.Version]'10.0') {
      Write-Host 'Using cipher suites order for Windows 7/2008R2/2012/2012R2.'
      $cipherSuitesOrder = @(
        'TLS_AES_256_GCM_SHA384',
        'TLS_CHACHA20_POLY1305_SHA256',
        'TLS_AES_128_GCM_SHA256',
        'TLS_AES_128_CCM_SHA256',
        'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P521',
        'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P384',
        'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P256',
        'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P521',
        'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P384',
        'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P256',
        'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P521',
        'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P384',
        'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P256',
        'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P521',
        'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P384',
        'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P256',
        'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P521',
        'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P384',
        'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P521',
        'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P384',
        'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P256',
        'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P521',
        'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P384',
        'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P521',
        'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P384',
        'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P256',
        'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P521',
        'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P384',
        'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P256',
        'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P521',
        'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P384',
        'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P256'
        # RSA us no longer considered secure
        #'TLS_RSA_WITH_AES_256_GCM_SHA384',
        #'TLS_RSA_WITH_AES_128_GCM_SHA256',
        #'TLS_RSA_WITH_AES_256_CBC_SHA256',
        #'TLS_RSA_WITH_AES_128_CBC_SHA256',
        #'TLS_RSA_WITH_AES_256_CBC_SHA',
        #'TLS_RSA_WITH_AES_128_CBC_SHA',
        #'TLS_RSA_WITH_3DES_EDE_CBC_SHA'
      )
    } else {
      Write-Host 'Using cipher suites order for Windows 10/2016 and later.'
      $cipherSuitesOrder = @(
        'TLS_AES_256_GCM_SHA384',
        'TLS_CHACHA20_POLY1305_SHA256',
        'TLS_AES_128_GCM_SHA256',
        'TLS_AES_128_CCM_SHA256',
        'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384'
        'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'
        'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384'
        'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256'
        'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA'
        'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA'
        'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384'
        'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256'
        'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384'
        'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256'
        #'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA'
        #'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA'
        # RSA is no longer considered secure
        #'TLS_RSA_WITH_AES_256_GCM_SHA384'
        #'TLS_RSA_WITH_AES_128_GCM_SHA256'
        #'TLS_RSA_WITH_AES_256_CBC_SHA256'
        #'TLS_RSA_WITH_AES_128_CBC_SHA256'
        #'TLS_RSA_WITH_AES_256_CBC_SHA'
        #'TLS_RSA_WITH_AES_128_CBC_SHA'
        #'TLS_RSA_WITH_3DES_EDE_CBC_SHA'
      )
    }
    $cipherSuitesAsString = [string]::join(',', $cipherSuitesOrder)
    New-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -Force >> $NULL
    New-ItemProperty -path 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -name 'Functions' -value $cipherSuitesAsString -PropertyType 'String' -Force >> $NULL
    Write-Host "Reordered Ciphersuite for Perfect Forward Secrecy."
    Write-Host ""

    # Disable HTTP2 which mitigates the SPDY vulnerability
    # HTTP2 will no longer be supported some Server 2016 -- only TLS
    New-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\HTTP\Parameters' -Name 'EnableHttp2Tls' -Value 0 -PropertyType 'DWord' -Force >> $NULL
    New-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\HTTP\Parameters' -Name 'EnableHttp2Cleartext' -Value 0 -PropertyType 'DWord' -Force >> $NULL
    Write-Host "Disabled HTTP2. (SPDY)"
    Write-Host ""

    # Force .NET framework to only use strong crypto
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727' -Name 'SchUseStrongCrypto' -Value '1' -PropertyType 'DWord' -Force >> $NULL
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -PropertyType 'DWord' -Force >> $NULL
    Write-Host "Forced .NET Framework v3.5 to use Strong Crypto."
    Write-Host "Forced .NET Framework v4 to use Strong Crypto."
    Write-Host ""

    # End Harden_SSL Function
}

###############################################################
###############    Clear Windows Start Menu     ###############
###############################################################

Function ClearDefaultStartMenu
{
    Write-Host "Clearing default start menu for NEW profiles."

    $StartMenuLayout = @('
 <LayoutModificationTemplate xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout" Version="1" xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification">
  <LayoutOptions StartTileGroupCellWidth="6" />
  <DefaultLayoutOverride>
    <StartLayoutCollection>
      <defaultlayout:StartLayout GroupCellWidth="6" xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout">
        <start:Group Name="" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout">
          <start:DesktopApplicationTile Size="2x2" Column="0" Row="0" DesktopApplicationLinkPath="%APPDATA%\Microsoft\Windows\Start Menu\Programs\System Tools\File Explorer.lnk" />
          <start:DesktopApplicationTile Size="2x2" Column="2" Row="0" DesktopApplicationLinkPath="%APPDATA%\Microsoft\Windows\Start Menu\Programs\Accessories\Snipping Tool.lnk" />
          <start:DesktopApplicationTile Size="2x2" Column="0" Row="2" DesktopApplicationLinkPath="%APPDATA%\Microsoft\Windows\Start Menu\Programs\Accessories\Internet Explorer.lnk" />
        </start:Group>
      </defaultlayout:StartLayout>
    </StartLayoutCollection>
  </DefaultLayoutOverride>
</LayoutModificationTemplate>
    ')

    Add-Content $env:TEMP\startmenulayout.xml $StartMenuLayout
    Import-StartLayout -LayoutPath $env:TEMP\startmenulayout.xml -MountPath $env:SYSTEMDRIVE\
    Remove-Item $env:TEMP\startmenulayout.xml

    Write-Host -ForegroundColor Yellow "Start Menu Cleared to Default Layout.`n"

    # End of ClearDefaultStartMenu function
}

######################################################################
###############    Apply Level 1 Security Settings     ###############
######################################################################

Function Applylvl1Security
{
    # Disable some built-in Windows tasks that are unecessary
    Get-ScheduledTask "Microsoft Compatibility Appraiser","Consolidator","ProgramDataUpdater","UsbCeip","KernelCeipTask","Microsoft-Windows-DiskDiagnosticDataCollector","GatherNetworkInfo","QueueReporting" -ErrorAction SilentlyContinue | Disable-ScheduledTask
    Write-Host "Disabled unnecessary `"Call Home`" scheduled tasks."

    # Set some default registry values
    New-ItemProperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -name 'SystemPaneSuggestionsEnabled' -value 0 -PropertyType 'DWord' -Force >> $NULL
    New-ItemProperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -name 'SoftLandingEnabled' -value 0 -PropertyType 'DWord' -Force >> $NULL
    New-ItemProperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -name 'RotatingLockScreenEnabled' -value 0 -PropertyType 'DWord' -Force >> $NULL
    New-ItemProperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -name 'PreInstalledAppsEnabled' -value 0 -PropertyType 'DWord' -Force >> $NULL
    New-ItemProperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -name 'PreInstalledAppsEverEnabled' -value 0 -PropertyType 'DWord' -Force >> $NULL
    New-ItemProperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -name 'PreInstalledAppsEverEnabled' -value 0 -PropertyType 'DWord' -Force >> $NULL
    New-ItemProperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -name 'OEMPreInstalledAppsEnabled' -value 0 -PropertyType 'DWord' -Force >> $NULL
    New-ItemProperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -name 'SilentInstallAppsEnabled' -value 0 -PropertyType 'DWord' -Force >> $NULL
    New-ItemProperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -name 'ContentDeliveryAllowed' -value 0 -PropertyType 'DWord' -Force >> $NULL
    New-ItemProperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -name 'SubscribedContentEnabled' -value 0 -PropertyType 'DWord' -Force >> $NULL
    New-ItemProperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -name 'ShowSyncProviderNotifications' -value 0 -PropertyType 'DWord' -Force >> $NULL

    # Disable App telemetry and inventory collection
    # According to MS, setting the AITEnable value to 1 actually Enables the DISABLEMENT of telemetry tracking for apps
    If (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat")
    {
        New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -Value 1 -PropertyType "DWord" -Force >> $NULL
        New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableInventory" -Value 1 -PropertyType "DWord" -Force >> $NULL
    }
    else
    {
        New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "AppCompat" -Force >> $NULL
        New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -Value 1 -PropertyType "DWord" -Force >> $NULL
        New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableInventory" -Value 1 -PropertyType "DWord" -Force >> $NULL
    }

    # Disable Cloud Content Suggestions, Tips, customer experience, etc.
    New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Cloud Content" -Name "DisableSoftLanding" -Value 1 -PropertyType "DWord" -Force >> $NULL
    New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Cloud Content" -Name "DisableWindowsConsumerFeatures" -Value 1 -PropertyType "DWord" -Force >> $NULL
    New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Cloud Content" -Name "DisableThirdPartySuggetsions" -Value 1 -PropertyType "DWord" -Force >> $NULL
    New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Cloud Content" -Name "DisableWindowsSpotlightFeatures" -Value 1 -PropertyType "DWord" -Force >> $NULL

    # Disable Telemetry, pre-release apps/features, and feedback notifications
    New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -PropertyType "DWord" -Force >> $NULL

    if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds")
    {
        New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "EnableConfigFlighting" -Value 0 -PropertyType "DWord" -Force >> $NULL
    }
    else
    {
        New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "PreviewBuilds" -Force >> $NULL
        New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "EnableConfigFlighting" -Value 0 -PropertyType "DWord" -Force >> $NULL
    }

    New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotSowFeedbackNotifications" -Value 1 -PropertyType "DWord" -Force >> $NULL

    # Set Edge to always send Do Not Track
    if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main")
    {
        New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name "DoNotTrack" -Value 1 -PropertyType "DWord" -Force >> $NULL
    }
    else
    {
        New-Item "HKLM:\SOFTWARE\Policies\Microsoft" -Name "MicrosoftEdge" -Force >> $NULL
        New-Item "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge" -Name "Main" -Force >> $NULL
        New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name "DoNotTrack" -Value 1 -PropertyType "DWord" -Force >> $NULL
    }

    # Disable advertising info sharing
    if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Device Metadata")
    {
        New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Value 1 -PropertyType "DWord" -Force >> $NULL
    }
    else
    {
        New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion" -Name "Device Metadata" -Force >> $NULL
        New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Value 1 -PropertyType "DWord" -Force >> $NULL
    }

    # Disable Windows Store Apps Auto Update
    # 2 - Disables Auto Update of Store Apps
    If (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore")
    {
        New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "AutoDownload" -Value 2 -PropertyType "DWord" -Force >> $NULL
    }
    else
    {
        New-Item "HKLM:\SOFTWARE\Policies\Microsoft" -Name "WindowsStore" -Force >> $NULL
        New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "AutoDownload" -Value 2 -PropertyType "DWord" -Force >> $NULL
    }

    # Disable MS MetaData retrieval -- STIG Windows Server 2012 Member Server Security STIG 2014-01-07 -- V-21964
    New-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Value 1 -Force >> $NULL
    Write-Host "Metadata retrieval disabled."


    Write-Host -ForegroundColor Yellow "Level 1 Security Settings Set.`n"

    # End of Applylvl1Security
}

######################################################################
###############        Apply Privacy Settings          ###############
######################################################################

Function ApplyPrivSettings
{

    # Disable Windows Media Player Network Sharing
    Set-Service WMPNetworkSvc -StartupType Disabled
    Write-Host "Windows Media Player Network Sharing Disabled."
    # Disable diagnostics tracking
    Set-Service DiagTrack -StartupType Disabled
    Write-Host "Diagnostic tracking disabled."

    # Disable asking for Feedback
    New-ItemProperty "HKLM:\SOFTWARE\Microsoft\Siuf" -Name "NumberOfSIUFInPeriod" -value 0 -PropertyType "DWord" -Force >> $NULL
    New-ItemProperty "HKLM:\SOFTWARE\Microsoft\Siuf" -Name "PeriodInNanoSeconds" -Value 0 -PropertyType "DWord" -Force >> $NULL
    Write-Host "Disabed asking for Feedback."

    # Turn off Advertising ID
    if (Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo")
    {
        New-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0 -PropertyType "DWord" -Force >> $NULL
    }
    else
    {
        New-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion" -Name "AdvertisingInfo" -Force >> $NULL
        New-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0 -PropertyType "DWord" -Force >> $NULL
    }
    Write-Host "Turned off advertising ID."

    # Disable use of language to provide relevant advertising
    New-ItemProperty "HKCU:\Control Panel\International\User Profile" -Name "HttpAcceptLanguageOptOut" -Value 1 -PropertyType "DWord" -Force >> $NULL

    # Turn off Windows Program Tracking
    New-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackProgs" -Value 0 -PropertyType "DWord" -Force >> $NULL

    # Disable Diagnostics & Feedback
    New-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperienceWithDiagnosticDataEnabled" -Value 0 -PropertyType "DWord" -Force >> $NULL

    # Disable MS Ink from collecting info
    New-ItemProperty "HKCU:\Software\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Value 0 -PropertyType "DWord" -Force >> $NULL

    # Disable People notifications, taskbar icon, and people search.
    if (Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People\ShoulderTap")
    {
        New-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People\ShoulderTap" -Name "ShoulderTap" -Value 0 -PropertyType "DWord" -Force >> $NULL
    }
    else
    {
        New-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "ShoulderTap" -Force >> $NULL
        New-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People\ShoulderTap" -Name "ShoulderTap" -Value 0 -PropertyType "DWord" -Force >> $NULL
    }
    # Remove People icon from taskbar
    New-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Value 0 -PropertyType "DWord" -Force >> $NULL
    New-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContentEnabled-314563Enabled" -Value 0 -PropertyType "DWord" -Force >> $NULL

    # Disable Autoplay
    New-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Value 1 -PropertyType "DWord" -Force >> $NULL

    # Turn off search icon in taskbar
    # 0 - Disabled, 1 - search icon, 2 - search bar
    New-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 0 -PropertyType "DWord" -Force >> $NULL

    # Prevent search from using location services if serach is enabled
    New-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "AllowSearchToUseLocation" -Value 0 -PropertyType "DWord" -Force >> $NULL

    Write-Host -ForegroundColor Yellow "Privacy Settings Applied.`n"

    # End of ApplyPrivSettings function
}

#################################################################
###############       Harden RDP Settings       ###############
################################################################

Function Harden_RDP
{
    Write-Host "`n"
    Write-Host "---------------------------- RDP Server Hardening ------------------------------`n"
    Write-Host "Hardening RDP Settings for Best Practices...`n"
    Write-Host "--------------------------------------------------------------------------------`n"

    # Set proper security settings for RDP (FIPS-140 level encryption, NLA, etc.)
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'MinEncryptionLevel' -Value '4' -PropertyType 'DWord' -Force >> $NULL
    Write-Host "Set RDP to use FIPS-140 level encryption."
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'SecurityLayer' -Value '0' -PropertyType 'DWord' -Force >> $NULL
    Write-Host "Set RDP to 0 security in order to allow NLA to take place."
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'fDisableEncryption' -Value '0' -PropertyType 'DWord' -Force >> $NULL
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'FDisableClip' -Value '1' -PropertyType 'DWord' -Force >> $NULL
    Write-Host "Disabled Clipboard crossover."
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'fDisableEXE' -Value '1' -PropertyType 'DWord' -Force >> $NULL
    Write-Host "Disabled automatic run-executable on logon."
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'fInheritAutoLogon' -Value '0' -PropertyType 'DWord' -Force >> $NULL
    Write-Host "Disabled Auto-logon."
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Value '1' -PropertyType 'DWord' -Force >> $NULL
    Write-Host "Enabled Network Level Authentication."
    Write-Host "This automatically uses TLS for communication."

    Write-Host ""
    Write-Host -ForegroundColor Yellow "RDP Settings now hardened.`n"

    # End of Harden_RDP function
}

###############################################################
########         Remove News and Interests            #########
###############################################################

Function Remove_NewsInterests {
    Write-Host ""
    Write-Host "------------------------- Remove News and Interests ----------------------------"
    Write-Host ""
    Write-Host "Removing the Microsoft News and Interests..."
    Write-Host ""
    Write-Host "--------------------------------------------------------------------------------"
    Write-Host ""
    Write-Host "NOTE: Due to recent Windows updates, you may still need to turn off or 'hide' the News and Interests"

    # Set Registry entry to disable News and Interests
    New-ItemProperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds\FeedRepositoryState' -name 'FeedsNextRefreshIntervalMinutes' -value 60 -PropertyType 'DWord' -Force >> $NULL
    New-ItemProperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds\FeedRepositoryState' -name 'FeedsPrevRefreshIntervalMinutes' -value 60 -PropertyType 'DWord' -Force >> $NULL
    New-ItemProperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds\FeedRepositoryState' -name 'FeedEnabled' -value 0 -PropertyType 'DWord' -Force >> $NULL
    New-ItemProperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds\DSB' -name 'IsDynamicContentAvailable' -value 0 -PropertyType 'DWord' -Force >> $NULL
    New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds\DSB' -name 'IsEnabledByServer' -value 0 -PropertyType 'DWord' -Force >> $NULL
    New-ItemProperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds' -name 'ShellFeedsTaskbarViewMode' -value 2 -PropertyType 'DWord' -Force >> $NULL
    New-ItemProperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds' -name 'IsFeedsAvailable' -value 0 -PropertyType 'DWord' -Force >> $NULL
    Write-Host "News and Interests disabled."
}


#################################################################
###############       Pre-Execution Checks       ###############
################################################################

# Check if PowerShell is being run with Administrator Rights as a backup if "#Requires - RunAdAdministrator" Fails
$isadmin = [Security.Principal.WindowsIdentity]::GetCurrent().Groups -contains 'S-1-5-32-544'
if ( -not $isadmin )
{
    Write-Host "This script requires Administrative Permissions."
    Exit
}

#################################################################
###############    Prompt User for Selection     ###############
###############################################################

$options = @(
    "RemoveWinBloat"
    "RemoveXboxBloat"
    "RemoveOneDrive"
    "RemoveCortana"
    "Remove_NewsInterests"
    "ClearDefaultStartMenu"
    "Harden_SSL"
    "Harden_RDP"
    "Applylvl1Security"
    "ApplyPrivSettings"
)

# Call appropriate functions from options list above

foreach ($option in $options)
{
    $msg = 'Do you want to run ' + $option + '?   (y/n)'
    $response = Read-Host -Prompt $msg
    if ($response -like 'y*')
    {
        &$option
    }
}


Write-Host "Remeber to set your Execution policy back to RESTRICTED."

Write-Host "`n"
Write-Host "All Done.  Your machine is now bloat-free, well, Windows bloat-free anyway.`n"
Write-Host -ForegroundColor Red '---------- A computer restart may be required to apply all changes. ----------'
Exit