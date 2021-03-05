[Rainmeter]
ContextTitle		="SYSMonitor #VarSettings#"
ContextAction		=[!ActivateConfig "#ROOTCONFIG#\#Settings" "SYSMonitor.ini"]
ContextTitle2		="Refresh Fritz!Box Info"
ContextAction2		=[!CommandMeasure PowerShell-Get-FBWLANConfiguration Run][!CommandMeasure PowerShell-FBWANDSLInterfaceConfig Run][!CommandMeasure PowerShell-FBWANPPPInfo Run][!CommandMeasure PowerShell-FBCallList Run][!CommandMeasure PowerShell-FBInfo Run]
ContextTitle3		="Reconnect DSL"
ContextAction3		=[!CommandMeasure PowerShell-DSLReconnect Run]
ContextTitle4		="Reboot Fritz!Box"
ContextAction4		=[!CommandMeasure PowerShell-FBReboot Run]

[Variables]
;---- Style ----
@Include6=#@#Include\PanelStyleMid.inc


;---- PowerShell Execution FBInfo ----

[PowerShell-FBInfo]
Measure			=Plugin
Plugin			=RunCommand
Parameter		=powershell.exe -ExecutionPolicy Bypass -File "#@#Tools\Get-FBInfo.ps1" -FBIP "#FBIP#" -USER "#USER#" -PASS "#PASS#"
State			=Hide
OutputType		=ANSI
OutputFile		=#@#Tools\Get-FBInfo.log
UpdateDivider	=-1

[Fileparse-FBInfo]
Measure			=WebParser
URL				=file://#@#Tools\Get-FBInfo.log
RegExp			=(?siU)NewModelName.*: (.*)\R.*NewSoftwareVersion.*: (.*)\R.*NewUpTime.*: (.*)\R
DynamicVariables=1
UpdateRate		=20

[Measure_FBNewModelName]
Measure			=WebParser
URL				=[Fileparse-FBInfo]
StringIndex		=1
RegExpSubstitute=1
Substitute		=#FritzBoxFilter#
DynamicVariables=1
UpdateDivider	=600
ErrorString		=Unauthorized

[Measure_FBNewSoftwareVersion]
Measure			=WebParser
URL				=[Fileparse-FBInfo]
StringIndex		=2
DynamicVariables=1
UpdateRate		=600

[Measure_FBNewUpTime]
Measure			=WebParser
URL				=[Fileparse-FBInfo]
StringIndex		=3
DynamicVariables=1
UpdateRate		=600

[Measure_Uptime]
Measure			=UpTime
SecondsValue	=[Measure_FBNewUpTime]
Format			="%4!i!d, %3!i!h:%2!i!m"
DynamicVariables=1
UpdateDivider	=600


;---- PowerShell Execution FBWANDSLInterfaceConfig ----

[PowerShell-FBWANDSLInterfaceConfig]
Measure			=Plugin
Plugin			=RunCommand
Parameter		=powershell.exe -ExecutionPolicy Bypass -File "#@#Tools\Get-FBWANDSLInterfaceConfig.ps1" -FBIP "#FBIP#" -USER "#USER#" -PASS "#PASS#"
State			=Hide
OutputType		=ANSI
OutputFile		=#@#Tools\Get-FBWANDSLInterfaceConfig.log
UpdateDivider	=-1

[Fileparse-FBWANDSLInterfaceConfig]
Measure			=WebParser
URL				=file://#@#Tools\Get-FBWANDSLInterfaceConfig.log
RegExp			=(?siU)NewStatus.*: (.*)\R.*NewUpstreamCurrRate.*: (.*)\R.*NewDownstreamCurrRate.*: (.*)\R
DynamicVariables=1
UpdateRate		=20

[Measure_FBNewStatus]
Measure			=WebParser
URL				=[Fileparse-FBWANDSLInterfaceConfig]
StringIndex		=1
DynamicVariables=1
UpdateRate		=20

[Measure_FBUpstreamInKBITS]
Measure			=WebParser
URL				=[Fileparse-FBWANDSLInterfaceConfig]
StringIndex		=2
DynamicVariables=1
UpdateRate		=20

[Measure_FBUpstreamInBITS]
Measure			=Calc
Formula			=Measure_FBUpstreamInKBITS*1024
DynamicVariables=1
DynamicVariables=1
UpdateRate		=20

[Measure_FBUpstreamInBYTES]
Measure			=Calc
Formula			=(Measure_FBUpstreamInBITS/8)
DynamicVariables=1
UpdateDivider	=20

[Measure_FBDownstreamInKBITS]
Measure			=WebParser
URL				=[Fileparse-FBWANDSLInterfaceConfig]
StringIndex		=3
DynamicVariables=1
UpdateRate		=20

[Measure_FBDownstreamInBITS]
Measure			=Calc
Formula			=Measure_FBDownstreamInKBITS*1024
DynamicVariables=1
UpdateDivider	=20

[Measure_FBDownstreamInBYTES]
Measure			=Calc
Formula			=(Measure_FBDownstreamInBITS/8)
DynamicVariables=1
UpdateDivider	=20


;---- PowerShell Execution FBWANPPPInfo ----

[PowerShell-FBWANPPPInfo]
Measure			=Plugin
Plugin			=RunCommand
Parameter		=powershell.exe -ExecutionPolicy Bypass -File "#@#Tools\Get-FBWANPPPInfo.ps1" -FBIP "#FBIP#" -USER "#USER#" -PASS "#PASS#"
State			=Hide
OutputType		=ANSI
OutputFile		=#@#Tools\Get-FBWANPPPInfo.log
UpdateDivider	=-1

[Fileparse-FBWANPPPInfo]
Measure			=WebParser
URL				=file://#@#Tools\Get-FBWANPPPInfo.log
RegExp			=(?siU)NewConnectionStatus.*: (.*)\R.*NewExternalIPAddress.*: (.*)\R
DynamicVariables=1
UpdateRate		=20

[Measure_FBNewConnectionStatus]
Measure			=WebParser
URL				=[Fileparse-FBWANPPPInfo]
StringIndex		=1
DynamicVariables=1
UpdateRate		=20

[Measure_FBNewExternalIPAddress]
Measure			=WebParser
URL				=[Fileparse-FBWANPPPInfo]
StringIndex		=2
DynamicVariables=1
UpdateRate		=600


;---- PowerShell Execution FBWLANConfiguration ----

[PowerShell-Get-FBWLANConfiguration]
Measure			=Plugin
Plugin			=RunCommand
Parameter		=powershell.exe -ExecutionPolicy Bypass -File "#@#Tools\Get-FBWLANConfiguration.ps1" -FBIP "#FBIP#" -USER "#USER#" -PASS "#PASS#"
State			=Hide
OutputType		=ANSI
OutputFile		=#@#Tools\Get-FBWLANConfiguration.log
UpdateDivider	=-1

[Fileparse-FBWLANConfiguration]
Measure			=WebParser
URL				=file://#@#Tools\Get-FBWLANConfiguration.log
RegExp			=(?siU)NewStatus.*: (.*)\R.*NewSSID.*: (.*)\R.*NewBSSID.*: (.*)\R
DynamicVariables=1
UpdateRate		=20

[Measure_FBWLANStatus]
Measure			=WebParser
URL				=[Fileparse-FBWLANConfiguration]
StringIndex		=1
DynamicVariables=1
UpdateRate		=20

[Measure_FBWLANSSID]
Measure			=WebParser
URL				=[Fileparse-FBWLANConfiguration]
StringIndex		=2
DynamicVariables=1
UpdateRate		=600

[Measure_FBWLANMAC]
Measure			=WebParser
URL				=[Fileparse-FBWLANConfiguration]
StringIndex		=3
DynamicVariables=1
UpdateRate		=600


;---- PowerShell Execution DSL Reconnect ----

[PowerShell-DSLReconnect]
Measure			=Plugin
Plugin			=RunCommand
Parameter		=powershell.exe -ExecutionPolicy Bypass -File "#@#Tools\Invoke-DSLDisconnect.ps1" -FBIP "#FBIP#" -USER "#USER#" -PASS "#PASS#"
State			=Hide


;---- PowerShell Execution FB Reboot ----

[PowerShell-FBReboot]
Measure			=Plugin
Plugin			=RunCommand
Parameter		=powershell.exe -ExecutionPolicy Bypass -File "#@#Tools\FBReboot.ps1" -FBIP "#FBIP#" -USER "#USER#" -PASS "#PASS#"
State			=Hide


;---- PowerShell Execution FBCallList ----

[PowerShell-FBCallList]
Measure			=Plugin
Plugin			=RunCommand
Parameter		=powershell.exe -ExecutionPolicy Bypass -File "#@#Tools\Get-FBCallList.ps1" -FBIP "#FBIP#" -USER "#USER#" -PASS "#PASS#"
State			=Hide
OutputType		=ANSI
OutputFile		=#@#Tools\Get-FBCallList.log
UpdateDivider	=-1

[Fileparse-FBCallList]
Measure			=WebParser
URL				=file://#@#Tools\Get-FBCallList.log
RegExp			=(?siU)Type.*: [1-2].*Caller.*: (.*)\R.*Called.*: (.*)\R.*Name.*: (.*)\R.*Date.*: (.*)\R
DynamicVariables=1
UpdateRate		=600

[Measure_FBLastCaller]
Measure			=WebParser
URL				=[Fileparse-FBCallList]
StringIndex		=1
DynamicVariables=1
UpdateRate		=600

[Measure_FBLastCalled]
Measure			=WebParser
URL				=[Fileparse-FBCallList]
StringIndex		=2
DynamicVariables=1
UpdateRate		=600

[Measure_FBLastCallerName]
Measure			=WebParser
URL				=[Fileparse-FBCallList]
StringIndex		=3
DynamicVariables=1
UpdateRate		=600

[Measure_FBLastCallDate]
Measure			=WebParser
URL				=[Fileparse-FBCallList]
StringIndex		=4
DynamicVariables=1
UpdateRate		=600


;---- Local Network Measures related to max Internet Link Speed ----

[NetworkDownload]
Measure			=NetIn
Interface		=Best
UseBits			=1
NetInSpeed		=Measure_FBDownstreamInBITS
UpdateDivider	=1
DynamicVariables=1

[NetworkUpload]
Measure			=NetOut
Interface		=Best
UseBits			=1
NetOutSpeed		=Measure_FBUpstreamInBITS
UpdateDivider	=1
DynamicVariables=1


;---- Standard Meter ----	

[Info1IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Download#FritzBoxColoredIcons#.png
	X=(#PHeight#*0.1)
	Y=(#PHeight#*0.1)
	W=(#PHeight#*0.2)
	H=(#PHeight#*0.2)
	DynamicVariables=1
[Info1IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Download#FritzBoxColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.2)
	H=(#PHeight#*0.2)
	Hidden=#FritzBoxColoredIcons#
	DynamicVariables=1
[Info1TextA]
	Meter=String
	MeterStyle=PText | PInfo
	MeasureName=NetworkDownload
	X=(#PHeight#*0.25)r
	Y=(-#PHeight#*0.02)r
	Text=%1B/s
	Autoscale=1
	NumOfDecimals=1
	UpdateDivider=10
[Info1TextB]
	Meter=String
	MeterStyle=PText | PSize8
	StringAlign=Left
	X=0r
	Y=(#PHeight#*0.14)r
	MeasureName=Measure_FBDownstreamInBYTES
	MeasureName2=Measure_FBDownstreamInBITS
	Text=%1B/s | %2bit
	Autoscale=1
	NumOfDecimals=1
	DynamicVariables=1
	UpdateDivider=50

[Info2IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Upload#FritzBoxColoredIcons#.png
	X=(#PHeight#*0.1)
	Y=(#PHeight#*0.35)
	W=(#PHeight#*0.2)
	H=(#PHeight#*0.2)
	DynamicVariables=1
[Info2IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Upload#FritzBoxColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.2)
	H=(#PHeight#*0.2)
	Hidden=#FritzBoxColoredIcons#
	DynamicVariables=1
[Info2TextA]
	Meter=String
	MeterStyle=PText | PInfo
	MeasureName=NetworkUpload
	X=(#PHeight#*0.25)r
	Y=(-#PHeight#*0.02)r
	Text=%1B/s
	Autoscale=1
	NumOfDecimals=1
	UpdateDivider=10
[Info2TextB]
	Meter=String
	MeterStyle=PText | PSize8
	StringAlign=Left
	X=0r
	Y=(#PHeight#*0.14)r
	MeasureName=Measure_FBUpstreamInBYTES
	MeasureName2=Measure_FBUpstreamInBITS
	Text=%1B/s | %2bit
	Autoscale=1
	NumOfDecimals=1
	DynamicVariables=1
	UpdateDivider=50

;---- Fritz!Box ----

[FritzBox_Image]
	Meter=Image
	ImageName=#@#Images\General\FB7590-#FritzBoxColor#.png
	X=(#PHeight#*0.05)
	Y=(#PHeight#*0.6)
	W=(#PHeight#*0.99)
	DynamicVariables=1
	UpdateDivider=-1
	

[FritzBox_LED]
	Meter=Shape
	Shape=Rectangle (#PHeight#*0.55),(#PHeight#*0.79),(#PHeight#*0.045),(#PHeight#*0.10) | StrokeWidth (#PHeight#*0.003) | Stroke Color [#FBFontColor[#FritzBoxColor]] | Fill Lineargradient FBStatus[&Measure_FBNewStatus]
	Shape2=Rectangle (#PHeight#*0.63),(#PHeight#*0.79),(#PHeight#*0.045),(#PHeight#*0.10) | StrokeWidth (#PHeight#*0.003) | Stroke Color [#FBFontColor[#FritzBoxColor]] | Fill Lineargradient FBStatus[&Measure_FBWLANStatus]
	Shape3=Rectangle (#PHeight#*0.71),(#PHeight#*0.79),(#PHeight#*0.045),(#PHeight#*0.10) | StrokeWidth (#PHeight#*0.003) | Stroke Color [#FBFontColor[#FritzBoxColor]] | Fill Lineargradient FBStatusNeutral#FritzBoxColor#
	Shape4=Rectangle (#PHeight#*0.79),(#PHeight#*0.79),(#PHeight#*0.045),(#PHeight#*0.10) | StrokeWidth (#PHeight#*0.003) | Stroke Color [#FBFontColor[#FritzBoxColor]] | Fill Lineargradient FBStatus[&Measure_FBNewConnectionStatus]
	Shape5=Rectangle (#PHeight#*0.87),(#PHeight#*0.79),(#PHeight#*0.045),(#PHeight#*0.10) | StrokeWidth (#PHeight#*0.003) | Stroke Color [#FBFontColor[#FritzBoxColor]] | Fill Lineargradient FBStatusNeutral#FritzBoxColor#
	FBStatusNeutral1=90 | 80,80,80 ; 1.0 | 20,20,20 ; 0.0
	FBStatusNeutral0=90 | 160,160,160 ; 1.0 | 100,100,100 ; 0.0
	FBStatusEnabled=90 | 0,255,0 ; 1.0 | 0,200,0 ; 0.0
	FBStatusDisabled=90 | 255,0,0 ; 1.0 | 200,0,0 ; 0.0
	FBStatusUp=90 | 0,255,0 ; 1.0 | 0,200,0 ; 0.0
	FBStatusDown=90 | 255,0,0 ; 1.0 | 200,0,0 ; 0.0
	FBStatus=90 | 255,0,0 ; 1.0 | 200,0,0 ; 0.0
	FBStatusInitializing=90 | 255,255,0 ; 1.0 | 200,200,0 ; 0.0
	FBStatusConnected=90 | 0,255,0 ; 1.0 | 0,200,0 ; 0.0
	FBStatusDisconnected=90 | 255,0,0 ; 1.0 | 200,0,0 ; 0.0	
	FBStatusNoSignal=90 | 255,0,0 ; 1.0 | 200,0,0 ; 0.0	
	DynamicVariables=1
	UpdateDivider=50

[FritzBox_LED1Text]
	Meter=String
	MeterStyle=PText | PSize9
	FontColor=[#FBFontColor[#FritzBoxColor]]
	X=(#PHeight#*0.54)
	Y=(#PHeight#*0.78)
	Text=DSL
	Angle=(Rad(-90))
	UpdateDivider=-1

[FritzBox_LED2Text]
	Meter=String
	MeterStyle=PText | PSize9
	FontColor=[#FBFontColor[#FritzBoxColor]]
	X=(#PHeight#*0.08)r
	Y=0r
	Text=WLAN
	Angle=(Rad(-90))
	UpdateDivider=-1
	
[FritzBox_LED3Text]
	Meter=String
	MeterStyle=PText | PSize9
	FontColor=[#FBFontColor[#FritzBoxColor]]
	X=(#PHeight#*0.08)r
	Y=0r
	Text=Phone
	Angle=(Rad(-90))
	UpdateDivider=-1
	
[FritzBox_LED4Text]
	Meter=String
	MeterStyle=PText | PSize9
	FontColor=[#FBFontColor[#FritzBoxColor]]
	X=(#PHeight#*0.08)r
	Y=0r
	Text=Online
	Angle=(Rad(-90))
	UpdateDivider=-1

[FritzBox_LED5Text]
	Meter=String
	MeterStyle=PText | PSize9
	FontColor=[#FBFontColor[#FritzBoxColor]]
	X=(#PHeight#*0.08)r
	Y=0r
	Text=Info
	Angle=(Rad(-90))
	UpdateDivider=-1


;---- FritzBox Functions ----

[MouseOverButtonStyle]
	ImageName=#@#Images\Buttons\1px.png
	ImageTint=0,0,0,0
	Y=(#PHeight#*0.79)
	W=(#PHeight#*0.05)
	H=(#PHeight#*0.105)
	DynamicVariables=1
	UpdateDivider=-1
	
[FB_MouseOverInfoImage_DSL]
	Meter=Image
	MeterStyle=MouseOverButtonStyle
	X=(#PHeight#*0.55)
	MouseOverAction=[!ShowMeter FB_MouseOverInfo_DSL]
	MouseLeaveAction=[!HideMeter FB_MouseOverInfo_DSL]
[FB_MouseOverInfo_DSL]
	Meter=String
	MeasureName=Measure_Uptime
	MeterStyle=PText | PSize9
	FontColor=[#FBFontColor[#FritzBoxColor]]
	X=(#PHeight#*0.19)
	Y=(#PHeight#*0.63)
	Text=DSL Uptime:#CRLF#%1
	Hidden=1
	UpdateDivider=20

[FB_MouseOverInfoImage_WLAN]
	Meter=Image
	MeterStyle=MouseOverButtonStyle
	X=(#PHeight#*0.63)
	MouseOverAction=[!ShowMeter FB_MouseOverInfo_WLAN]
	MouseLeaveAction=[!HideMeter FB_MouseOverInfo_WLAN]
[FB_MouseOverInfo_WLAN]
	Meter=String
	MeasureName=Measure_FBWLANSSID
	MeterStyle=PText | PSize9
	FontColor=[#FBFontColor[#FritzBoxColor]]
	X=(#PHeight#*0.19)
	Y=(#PHeight#*0.63)
	Text=SSID:#CRLF#%1
	Hidden=1
	UpdateDivider=20
	
[FB_MouseOverInfoImage_Phone]
	Meter=Image
	MeterStyle=MouseOverButtonStyle
	X=(#PHeight#*0.71)
	MouseOverAction=[!HideMeterGroup FBInfo][!ShowMeterGroup LastCall]

[FB_MouseOverInfoImage_Connection]
	Meter=Image
	MeterStyle=MouseOverButtonStyle
	X=(#PHeight#*0.79)
	MouseOverAction=[!ShowMeter FB_MouseOverInfo_Connection]
	MouseLeaveAction=[!HideMeter FB_MouseOverInfo_Connection]
[FB_MouseOverInfo_Connection]
	Meter=String
	MeasureName=Measure_FBNewExternalIPAddress
	MeterStyle=PText | PSize9
	FontColor=[#FBFontColor[#FritzBoxColor]]
	X=(#PHeight#*0.19)
	Y=(#PHeight#*0.63)
	Text=External IP:#CRLF#%1
	Hidden=1
	UpdateDivider=20
	
[FB_MouseOverInfoImage_Info]
	Meter=Image
	MeterStyle=MouseOverButtonStyle
	X=(#PHeight#*0.87)
	MouseOverAction=[!ShowMeter FB_MouseOverInfo_Info]
	MouseLeaveAction=[!HideMeter FB_MouseOverInfo_Info]
[FB_MouseOverInfo_Info]
	Meter=String
	MeasureName=Measure_FBNewSoftwareVersion
	MeterStyle=PText | PSize9
	FontColor=[#FBFontColor[#FritzBoxColor]]
	X=(#PHeight#*0.19)
	Y=(#PHeight#*0.63)
	Text=Firmware:#CRLF#%1
	Hidden=1
	UpdateDivider=20

[Title]
	Meter=String
	MeasureName=Measure_FBNewModelName
	MeterStyle=PText | PTitle
	Text=#FritzBoxName#
	UpdateDivider=20
	Group=FBInfo


;---- Call List ----

[CallListBackground]
	Meter=Shape
	Shape=Rectangle (#PHeight#*0.040),(#PHeight#*0.040),(#PHeight#),(#PHeight#),(#PHeight#*0.032) | Fill Color 0,0,0,210 | StrokeWidth 0
	DynamicVariables=1
	AntiAlias=1
	Updatedivider=-1
	Group=LastCall
	Hidden=1
	LeftMouseUpAction=[!SetClip [Measure_FBLastCaller]]
	MouseLeaveAction=[!ShowMeterGroup FBInfo][!HideMeterGroup LastCall]

[CallListTitle]
	Meter=String
	MeterStyle=PText | PTitle
	Text=#VarLastCall#
	UpdateDivider=20
	Group=LastCall
	Hidden=1
	
[CallList_Caller]
	Meter=String
	MeasureName=Measure_FBLastCaller
	MeterStyle=PText | PInfo | PCenterMid
	FontColor=210,210,210
	Y=(#PHeight#*0.1)
	Text=%1
	Group=LastCall
	Hidden=1
	
[CallList_Name]
	Meter=String
	MeasureName=Measure_FBLastCallerName
	MeterStyle=PText | PInfo | PCenterMid
	FontColor=210,210,210
	Y=(#PHeight#*0.3)
	Text=%1
	Group=LastCall
	Hidden=1
	
[CallList_Called]
	Meter=String
	MeasureName=Measure_FBLastCalled
	MeterStyle=PText | PInfo | PCenterMid
	FontColor=210,210,210
	Y=(#PHeight#*0.5)
	Text=%1
	Group=LastCall
	Hidden=1
	
[CallList_Date]
	Meter=String
	MeasureName=Measure_FBLastCallDate
	FontColor=210,210,210
	MeterStyle=PText | PInfo | PCenterMid
	Y=(#PHeight#*0.7)
	Text=%1
	Group=LastCall
	Hidden=1
	
	
;---- Skin Functions ----

[AutoRefreshOption]
Measure				=Calc
Formula				=AutoRefreshOption%3600+1
DynamicVariables	=1
Updatedivider		=10
IfCondition			=(AutoRefreshOption = 3)
IfTrueAction		=[!CommandMeasure PowerShell-Get-FBWLANConfiguration Run][!CommandMeasure PowerShell-FBWANDSLInterfaceConfig Run][!CommandMeasure PowerShell-FBWANPPPInfo Run][!CommandMeasure PowerShell-FBCallList Run][!CommandMeasure PowerShell-FBInfo Run]

[KlickFunctions]
Meter=Shape
MeterStyle=KlickFunctionsBG

[ChangePanelSize]
Meter=Shape
MeterStyle=Change-Panel-Size