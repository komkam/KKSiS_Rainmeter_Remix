[Variables]

;---- Style ----
@Include6=#@#Include\PanelStyleMid.inc


;---- Windows Measures ----

[Measure_LANIN]
Measure			=NetIn
Interface		=#LAN2Interface#
UseBits			=1
NetInSpeed		=(#LAN2MaxInValueInMBits#*1024*1024)
UpdateDivider	=1
DynamicVariables=1

[Measure_MaxIn]
Measure			=Calc
Formula			=#LAN2MaxInValueInMBits#*1024*1024
UpdateDivider	=20
DynamicVariables=1

[Measure_MaxIn_inBytes]
Measure			=Calc
Formula			=Measure_MaxIn/8
UpdateDivider	=20
DynamicVariables=1

[Measure_LANOUT]
Measure			=NetOut
Interface		=#LAN2Interface#
UseBits			=1
NetInSpeed		=(#LAN2MaxOutValueInMBits#*1024*1024)
UpdateDivider	=1
DynamicVariables=1

[Measure_MaxOut]
Measure			=Calc
Formula			=#LAN2MaxOutValueInMBits#*1024*1024
UpdateDivider	=20
DynamicVariables=1

[Measure_MaxOut_inBytes]
Measure			=Calc
Formula			=Measure_MaxOut/8
UpdateDivider	=20
DynamicVariables=1

[Measure_LANName]
Measure			=Plugin
Plugin			=SysInfo
SysInfoType		=ADAPTER_DESCRIPTION
SysInfoData		=#LAN2Interface#
Substitute		=#Network2FilterWindows#
UpdateDivider	=10
DynamicVariables=1
UpdateDivider	=-1

[Measure_LANIP]
Measure			=Plugin
Plugin			=SysInfo
SysInfoType		=IP_ADDRESS
SysInfoData		=#LAN2Interface#
UpdateDivider	=10
DynamicVariables=1
UpdateDivider	=50

[Measure_InternetConnectivity]
Measure			=Plugin
Plugin			=SysInfo
SysInfoType		=LAN_CONNECTIVITY
SysInfoData		=#LAN2Interface#
DynamicVariables=0
UpdateDivider	=10


;---- Bar Calculation ----

[SmoothBar]
Measure			=Calc
Formula			=100-100*(Measure_LANIN*8/Measure_MaxIn)
MaxValue		=100
MinValue		=0
UpdateDivider	=1
AverageSize		=40


;---- Standard Meter ----

[Info1IconA]
	Meter=Image
	ImageName=#@#Images\Icons\NetIn#Network2ColoredIcons#.png
	X=(#PHeight#*0.1)
	Y=(#PHeight#*0.1)
	W=(#PHeight#*0.2)
	H=(#PHeight#*0.2)
	DynamicVariables=1
[Info1IconB]
	Meter=Image
	ImageName=#@#Images\Icons\NetIn#Network2ColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.2)
	H=(#PHeight#*0.2)
	Hidden=#Network2ColoredIcons#
	DynamicVariables=1
[Info1TextA]
	Meter=String
	MeterStyle=PText | PInfo
	MeasureName=Measure_LANIN
	X=(#PHeight#*0.25)r
	Text=%1B/s
	Autoscale=1
	NumOfDecimals=1
	UpdateDivider=10
[Info1TextB]
	Meter=String
	MeterStyle=PText | PSize7
	StringAlign=Left
	X=0r
	Y=(#PHeight#*0.12)r
	MeasureName=Measure_MaxIn_inBytes
	Text=%1B/s
	Autoscale=1
	NumOfDecimals=1
	DynamicVariables=1
	UpdateDivider=50
	
[Info2IconA]
	Meter=Image
	ImageName=#@#Images\Icons\NetOut#Network2ColoredIcons#.png
	X=(-#PHeight#*0.25)r
	Y=(#PHeight#*0.16)r
	W=(#PHeight#*0.2)
	H=(#PHeight#*0.2)
	DynamicVariables=1
[Info2IconB]
	Meter=Image
	ImageName=#@#Images\Icons\NetOut#Network2ColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.2)
	H=(#PHeight#*0.2)
	Hidden=#Network2ColoredIcons#
	DynamicVariables=1
[Info2TextA]
	Meter=String
	MeterStyle=PText | PInfo
	MeasureName=Measure_LANOUT
	X=(#PHeight#*0.25)r
	Text=%1B/s
	Autoscale=1
	NumOfDecimals=1
	UpdateDivider=10
[Info2TextB]
	Meter=String
	MeterStyle=PText | PSize7
	StringAlign=Left
	X=0r
	Y=(#PHeight#*0.12)r
	MeasureName=Measure_MaxOut_inBytes
	Text=%1B/s
	Autoscale=1
	NumOfDecimals=1
	DynamicVariables=1
	UpdateDivider=50
	
[Info3IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Chip#Network2ColoredIcons#.png
	X=(-#PHeight#*0.2)r
	Y=(#PHeight#*0.14)r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	DynamicVariables=1
[Info3IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Chip#Network2ColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	Hidden=#Network2ColoredIcons#
	DynamicVariables=1
[Info3Text]
	Meter=String
	MeterStyle=PText | PSize7
	X=(#PHeight#*0.2)r
	Y=(#PHeight#*0.01)r
	MeasureName=Measure_LANIP
	Text=%1
	NumOfDecimals=1
	DynamicVariables=1

[Info4Icon]
	Meter=Image
	ImageName=#@#Images\Icons\[Measure_InternetConnectivity]#Network2ColoredIcons#.png
	X=(-#PHeight#*0.2)r
	Y=(#PHeight#*0.16)r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	DynamicVariables=1
[Info4IconB]
	Meter=Image
	ImageName=#@#Images\Icons\[Measure_InternetConnectivity]#Network2ColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	Hidden=#GPUColoredIcons#
	DynamicVariables=1
[Info4Text]
	Meter=String
	MeterStyle=PText | PSize7
	X=(#PHeight#*0.2)r
	Y=(#PHeight#*0.01)r
	Text=Internet


[Title]
Meter=String
MeterStyle=PText | PTitle
MeasureName=Measure_LANName
Text=#LAN2NameWin#
DynamicVariables=1
Updatedivider=-1


;---- Bar ----

[Bar1]
Meter=Shape
MeterStyle=BarStyle-VRx1
UpdateDivider=1
Hidden=#Network2HideBar#

[Bar1Measure]
Meter=Bar
MeterStyle=BarStyle-VRx1Measure
MeasureName=SmoothBar
UpdateDivider=1
Hidden=#Network2HideBar#

[Bar1Stroke]
Meter=Shape
MeterStyle=BarStyle-VRx1Stroke
UpdateDivider=1
Hidden=#Network2HideBar#


;---- Skin Functions ----

[KlickFunctions]
Meter=Shape
MeterStyle=KlickFunctionsBG
LeftMouseUpAction=[Shell:::{7007ACC7-3202-11D1-AAD2-00805FC1270E}]

[ChangePanelSize]
Meter=Shape
MeterStyle=Change-Panel-Size