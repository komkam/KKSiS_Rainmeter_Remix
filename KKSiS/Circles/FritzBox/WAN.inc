[Rainmeter]
ContextTitle		="SYSMonitor #VarSettings#"
ContextAction		=[!ActivateConfig "#ROOTCONFIG#\#Settings" "SYSMonitor.ini"]
ContextTitle2		="Refresh Fritz!Box Info"
ContextAction2		=[!CommandMeasure PowerShell-Get-FBWLANConfiguration Run][!CommandMeasure PowerShell-FBWANPPPInfo Run][!CommandMeasure PowerShell-FBCallList Run][!CommandMeasure PowerShell-FBInfo Run]
ContextTitle3		="Reboot Fritz!Box"
ContextAction3		=[!CommandMeasure PowerShell-FBReboot Run]


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
RegExp			=(?siU)NewModelName.*: (.*)\R.*NewSoftwareVersion.*: (.*)\R
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
RegExp			=(?siU)NewConnectionStatus.*: (.*)\R.*NewUpstreamMaxBitRate.*: (.*)\R.*NewDownstreamMaxBitRate.*: (.*)\R.*NewExternalIPAddress.*: (.*)\R
DynamicVariables=1
UpdateRate		=20

[Measure_FBNewConnectionStatus]
Measure			=WebParser
URL				=[Fileparse-FBWANPPPInfo]
StringIndex		=1
DynamicVariables=1
UpdateRate		=20

[Measure_FBUpstreamInKBITS]
Measure			=WebParser
URL				=[Fileparse-FBWANPPPInfo]
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
URL				=[Fileparse-FBWANPPPInfo]
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

[Measure_FBNewExternalIPAddress]
Measure			=WebParser
URL				=[Fileparse-FBWANPPPInfo]
StringIndex		=4
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


[SmoothLeftRoundline]
Measure			=Calc
Formula			=100-100*((NetworkDownload+0.01)/(Measure_FBDownstreamInBYTES+0.1))
UpdateDivider	=1
AverageSize		=40

[SmoothRightRoundline]
Measure			=Calc
Formula			=100-100*((NetworkUpload+0.01)/(Measure_FBUpstreamInBYTES+0.1))
UpdateDivider	=1
AverageSize		=40


;---- Roundline 0 - 100 ----

[Measure_Roundline-Left]
Meter=Roundline
MeterStyle=Roundline-Left
MeasureName=SmoothLeftRoundline
ValueRemainder=100
UpdateDivider=1

[Measure_Roundline-Right]
Meter=Roundline
MeterStyle=Roundline-Right
MeasureName=SmoothRightRoundline
ValueRemainder=100
UpdateDivider=1

[LD-20]
Meter=Roundline
MeterStyle=LineDivider
StartAngle=(Rad(-199.3))
[LD-40]
Meter=Roundline
MeterStyle=LineDivider
StartAngle=(Rad(-172.3))
[LD-60]
Meter=Roundline
MeterStyle=LineDivider
StartAngle=(Rad(-145.3))
[LD-80]
Meter=Roundline
MeterStyle=LineDivider
StartAngle=(Rad(-118.3))
[LD+80]
Meter=Roundline
MeterStyle=LineDivider
StartAngle=(Rad(-62.7))
[LD+60]
Meter=Roundline
MeterStyle=LineDivider
StartAngle=(Rad(-35.7))
[LD+40]
Meter=Roundline
MeterStyle=LineDivider
StartAngle=(Rad(-8.7))
[LD+20]
Meter=Roundline
MeterStyle=LineDivider
StartAngle=(Rad(18.3))

[GlossyEffect]
Meter=Shape
MeterStyle=GlossyEffectStyle


;---- Roundline Left Meter ----

[SensorUnit]
	Meter=String
	MeterStyle=CText | CSize6 | CCenter
	Y=(#CRadius#*0.080)
	Text=b/s
	Autoscale=1
	NumOfDecimals=1
	Hidden=#FritzBoxHideRLLabel#
	UpdateDivider=-1
	
[SensorLeftMax]
	Meter=String
	MeterStyle=CText | CSize6
	MeasureName=Measure_FBDownstreamInBITS
	StringAlign=Right
	X=(#CRadius#*0.980)
	Y=(#CRadius#*0.160)
	Text=%1
	Autoscale=1
	NumOfDecimals=0
	Hidden=#FritzBoxHideRLLabel#
	UpdateDivider=50
	
[SensorLeftMin]
	Meter=String
	MeterStyle=CText | CSize6
	StringAlign=Right
	Angle=(Rad(-45))
	X=(#CRadius#*0.396)
	Y=(#CRadius#*1.454)
	Text=0
	Autoscale=1
	Hidden=#FritzBoxHideRLLabel#
	UpdateDivider=-1

;---- Roundline Right Meter ----

[SensorRightMax]
	Meter=String
	MeterStyle=CText | CSize6
	MeasureName=Measure_FBUpstreamInBITS
	StringAlign=Left
	X=(#CRadius#*1.020)
	Y=(#CRadius#*0.160)
	Text=%1
	Autoscale=1
	NumOfDecimals=0
	Hidden=#FritzBoxHideRLLabel#
	UpdateDivider=50
	
[SensorRightMin]
	Meter=String
	MeterStyle=CText | CSize6
	StringAlign=Left
	Angle=(Rad(45))
	X=(#CRadius#*1.604)
	Y=(#CRadius#*1.454)
	Text=0
	Hidden=#FritzBoxHideRLLabel#
	UpdateDivider=-1


;---- Fritz!Box ----

[FritzBox_Image]
	Meter=Image
	ImageName=#@#Images\General\FB7590-#FritzBoxColor#.png
	X=(#CRadius#*0.35)
	Y=(#CRadius#*0.76)
	W=(#CRadius#*1.3)
	DynamicVariables=1
	UpdateDivider=-1
	
[FritzBox_LED]
	Meter=Shape
	Shape=Rectangle (#CRadius#*1.05),(#CRadius#*1.0),(#CRadius#*0.06),(#CRadius#*0.13) | StrokeWidth (#CRadius#*0.003) | Stroke Color [#FBFontColor[#FritzBoxColor]] | Fill Lineargradient FBStatus[&Measure_FBNewConnectionStatus]
	Shape2=Rectangle (#CRadius#*1.15),(#CRadius#*1.0),(#CRadius#*0.06),(#CRadius#*0.13) | StrokeWidth (#CRadius#*0.003) | Stroke Color [#FBFontColor[#FritzBoxColor]] | Fill Lineargradient FBStatus[&Measure_FBWLANStatus]
	Shape3=Rectangle (#CRadius#*1.25),(#CRadius#*1.0),(#CRadius#*0.06),(#CRadius#*0.13) | StrokeWidth (#CRadius#*0.003) | Stroke Color [#FBFontColor[#FritzBoxColor]] | Fill Lineargradient FBStatusNeutral#FritzBoxColor#
	Shape4=Rectangle (#CRadius#*1.35),(#CRadius#*1.0),(#CRadius#*0.06),(#CRadius#*0.13) | StrokeWidth (#CRadius#*0.003) | Stroke Color [#FBFontColor[#FritzBoxColor]] | Fill Lineargradient FBStatus[&Measure_FBNewConnectionStatus]
	Shape5=Rectangle (#CRadius#*1.45),(#CRadius#*1.0),(#CRadius#*0.06),(#CRadius#*0.13) | StrokeWidth (#CRadius#*0.003) | Stroke Color [#FBFontColor[#FritzBoxColor]] | Fill Lineargradient FBStatusNeutral#FritzBoxColor#
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
	MeterStyle=CText | CSize8
	FontColor=[#FBFontColor[#FritzBoxColor]]
	X=(#CRadius#*1.04)
	Y=(#CRadius#*0.99)
	Text=DSL
	Angle=(Rad(-90))
	UpdateDivider=-1

[FritzBox_LED2Text]
	Meter=String
	MeterStyle=CText | CSize8
	FontColor=[#FBFontColor[#FritzBoxColor]]
	X=(#CRadius#*0.1)r
	Y=0r
	Text=WLAN
	Angle=(Rad(-90))
	UpdateDivider=-1
	
[FritzBox_LED3Text]
	Meter=String
	MeterStyle=CText | CSize8
	FontColor=[#FBFontColor[#FritzBoxColor]]
	X=(#CRadius#*0.1)r
	Y=0r
	Text=Phone
	Angle=(Rad(-90))
	UpdateDivider=-1
	
[FritzBox_LED4Text]
	Meter=String
	MeterStyle=CText | CSize8
	FontColor=[#FBFontColor[#FritzBoxColor]]
	X=(#CRadius#*0.1)r
	Y=0r
	Text=Online
	Angle=(Rad(-90))
	UpdateDivider=-1

[FritzBox_LED5Text]
	Meter=String
	MeterStyle=CText | CSize8
	FontColor=[#FBFontColor[#FritzBoxColor]]
	X=(#CRadius#*0.1)r
	Y=0r
	Text=Info
	Angle=(Rad(-90))
	UpdateDivider=-1
	

;---- FritzBox Functions ----

[KlickFunctions]
Meter=Shape
MeterStyle=KlickFunctionsBG
UpdateDivider=-1

[MouseOverButtonStyle]
	ImageName=#@#Images\Buttons\1px.png
	ImageTint=0,0,0,0
	Y=(#CRadius#*1.0)
	W=(#CRadius#*0.062)
	H=(#CRadius#*0.13)
	DynamicVariables=1
	UpdateDivider=-1
	
[FB_MouseOverInfoImage_DSL]
	Meter=Image
	MeterStyle=MouseOverButtonStyle
	X=(#CRadius#*1.05)
	MouseOverAction=[!ShowMeter FB_MouseOverInfo_DSL]
	MouseLeaveAction=[!HideMeter FB_MouseOverInfo_DSL]
[FB_MouseOverInfo_DSL]
	Meter=String
	MeterStyle=CText | CSize7
	FontColor=[#FBFontColor[#FritzBoxColor]]
	X=(#CRadius#*0.54)
	Y=(#CRadius#*0.8)
	Text=External#CRLF#Modem
	Hidden=1
	UpdateDivider=20

[FB_MouseOverInfoImage_WLAN]
	Meter=Image
	MeterStyle=MouseOverButtonStyle
	X=(#CRadius#*1.15)
	MouseOverAction=[!ShowMeter FB_MouseOverInfo_WLAN]
	MouseLeaveAction=[!HideMeter FB_MouseOverInfo_WLAN]
[FB_MouseOverInfo_WLAN]
	Meter=String
	MeasureName=Measure_FBWLANSSID
	MeterStyle=CText | CSize7
	FontColor=[#FBFontColor[#FritzBoxColor]]
	X=(#CRadius#*0.54)
	Y=(#CRadius#*0.8)
	Text=SSID:#CRLF#%1
	Hidden=1
	UpdateDivider=20
	
[FB_MouseOverInfoImage_Phone]
	Meter=Image
	MeterStyle=MouseOverButtonStyle
	X=(#CRadius#*1.25)
	MouseOverAction=[!HideMeterGroup FBInfo][!ShowMeterGroup LastCall]

[FB_MouseOverInfoImage_Connection]
	Meter=Image
	MeterStyle=MouseOverButtonStyle
	X=(#CRadius#*1.35)
	MouseOverAction=[!ShowMeter FB_MouseOverInfo_Connection]
	MouseLeaveAction=[!HideMeter FB_MouseOverInfo_Connection]
[FB_MouseOverInfo_Connection]
	Meter=String
	MeasureName=Measure_FBNewExternalIPAddress
	MeterStyle=CText | CSize7
	FontColor=[#FBFontColor[#FritzBoxColor]]
	X=(#CRadius#*0.54)
	Y=(#CRadius#*0.8)
	Text=External IP:#CRLF#%1
	Hidden=1
	UpdateDivider=20
	
[FB_MouseOverInfoImage_Info]
	Meter=Image
	MeterStyle=MouseOverButtonStyle
	X=(#CRadius#*1.45)
	MouseOverAction=[!ShowMeter FB_MouseOverInfo_Info]
	MouseLeaveAction=[!HideMeter FB_MouseOverInfo_Info]
[FB_MouseOverInfo_Info]
	Meter=String
	MeasureName=Measure_FBNewSoftwareVersion
	MeterStyle=CText | CSize7
	FontColor=[#FBFontColor[#FritzBoxColor]]
	X=(#CRadius#*0.54)
	Y=(#CRadius#*0.8)
	Text=Firmware:#CRLF#%1
	Hidden=1
	UpdateDivider=20


;---- Standard Meter ----	

[Info1IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Download#FritzBoxColoredIcons#.png
	X=(#CRadius#*0.6)
	Y=(#CRadius#*0.45)
	W=(#CRadius#*0.25)
	H=(#CRadius#*0.25)
	DynamicVariables=1
	UpdateDivider=-1	
[Info1IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Download#FritzBoxColoredIcons#.png
	ImageTint=#Circle-ButtonColor#
	X=0r
	Y=0r
	W=(#CRadius#*0.25)
	H=(#CRadius#*0.25)
	Hidden=#FritzBoxColoredIcons#
	DynamicVariables=1
	UpdateDivider=-1
[Info1TextA]
	Meter=String
	MeterStyle=CText | CInfo
	X=(#CRadius#*0.3)r
	MeasureName=NetworkDownload
	Text=%1B/s
	Autoscale=1
	NumOfDecimals=1
	UpdateDivider=10
[Info1TextB]
	Meter=String
	MeterStyle=CText | CSize6
	StringAlign=Left
	X=0r
	Y=(#CRadius#*0.15)r
	MeasureName=Measure_FBDownstreamInBYTES
	Text=%1B/s
	Autoscale=1
	NumOfDecimals=1
	DynamicVariables=1
	UpdateDivider=50
	
[Info2IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Upload#FritzBoxColoredIcons#.png
	X=(#CRadius#*0.6)
	Y=(#CRadius#*1.2)
	W=(#CRadius#*0.25)
	H=(#CRadius#*0.25)
	DynamicVariables=1
	UpdateDivider=-1
[Info2IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Upload#FritzBoxColoredIcons#.png
	ImageTint=#Circle-ButtonColor#
	X=0r
	Y=0r
	W=(#CRadius#*0.25)
	H=(#CRadius#*0.25)
	Hidden=#FritzBoxColoredIcons#
	DynamicVariables=1
	UpdateDivider=-1
[Info2TextA]
	Meter=String
	MeterStyle=CText | CInfo
	X=(#CRadius#*0.3)r
	MeasureName=NetworkUpload
	Text=%1B/s
	Autoscale=1
	NumOfDecimals=1
	UpdateDivider=10
[Info2TextB]
	Meter=String
	MeterStyle=CText | CSize6
	StringAlign=Left
	X=0r
	Y=(#CRadius#*0.15)r
	MeasureName=Measure_FBUpstreamInBYTES
	Text=%1B/s
	Autoscale=1
	NumOfDecimals=1
	DynamicVariables=1
	UpdateDivider=50


;---- Title ----

[Title]
	Meter=String
	MeasureName=Measure_FBNewModelName
	MeterStyle=CText | CTitle
	Text=#FritzBoxName#
	UpdateDivider=20
	Group=FBInfo

	
;---- Call List ----

[CallListTitle]
	Meter=String
	MeterStyle=CText | CTitle
	Text=#VarLastCall#
	Y=(#CRadius#*1.7)
	UpdateDivider=20
	Group=LastCall
	Hidden=1

[CallListBackground]
	Meter=Shape
	Shape=Ellipse (#CRadius#),(#CRadius#),(#CRadius#*0.72),(#CRadius#*0.72) | Fill Color 0,0,0,210 | StrokeWidth 0
	DynamicVariables=1
	AntiAlias=1
	Updatedivider=-1
	Group=LastCall
	Hidden=1
	LeftMouseUpAction=[!SetClip [Measure_FBLastCaller]]
	MouseLeaveAction=[!ShowMeterGroup FBInfo][!HideMeterGroup LastCall]

[CallList_Caller]
	Meter=String
	MeasureName=Measure_FBLastCaller
	MeterStyle=CText | CInfo | CCenter
	FontColor=210,210,210
	Y=(#CRadius#*0.5)
	Text=%1
	Group=LastCall
	Hidden=1
	
[CallList_Name]
	Meter=String
	MeasureName=Measure_FBLastCallerName
	MeterStyle=CText | CInfo | CCenter
	FontColor=210,210,210
	Y=(#CRadius#*0.75)
	Text=%1
	Group=LastCall
	Hidden=1
	
[CallList_Called]
	Meter=String
	MeasureName=Measure_FBLastCalled
	MeterStyle=CText | CInfo | CCenter
	FontColor=210,210,210
	Y=(#CRadius#*1.0)
	Text=%1
	Group=LastCall
	Hidden=1
	
[CallList_Date]
	Meter=String
	MeasureName=Measure_FBLastCallDate
	FontColor=210,210,210
	MeterStyle=CText | CInfo | CCenter
	Y=(#CRadius#*1.25)
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
IfTrueAction		=[!CommandMeasure PowerShell-Get-FBWLANConfiguration Run][!CommandMeasure PowerShell-FBWANPPPInfo Run][!CommandMeasure PowerShell-FBCallList Run][!CommandMeasure PowerShell-FBInfo Run]

[ChangeCircleSize]
Meter=Shape
MeterStyle=Change-Circle-Size
UpdateDivider=-1


