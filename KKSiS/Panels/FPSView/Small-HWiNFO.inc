[Variables]
;---- Style ----
@Include5=#@#Include\PanelStyleSmall.inc
;---- Sensors ----
@Include6=#@#HWiNFO-Sensors.inc


;---- Standard Windows Measures ----

[Measure_ScreenWidth]
Measure				=Plugin
Plugin				=SysInfo
SysInfoType			=SCREEN_WIDTH
SysInfoData			=#FPSViewDisplayID#
DynamicVariables	=1
UpdateDivider		=100

[Measure_ScreenHeight]
Measure				=Plugin
Plugin				=SysInfo
SysInfoType			=SCREEN_HEIGHT
SysInfoData			=#FPSViewDisplayID#
DynamicVariables	=1
UpdateDivider		=100


;---- Standard HWiNFO Measures ----

[Measure_FPS]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#GPU-FPS_Id#
HWiNFOSensorInstance=#GPU-FPS_Instance#
HWiNFOEntryId		=#GPU-FPS_EntryId#
HWiNFOType			=CurrentValue
IfEqualValue		=0
IfEqualAction		=[!HideMeterGroup GameON][!ShowMeterGroup GameOFF]
IfAboveValue		=0
IfAboveAction		=[!HideMeterGroup GameOFF][!ShowMeterGroup GameON]
IfCondition			=(#FPSViewHideDisplayRes# = 1)
IfTrueAction		=[!HideMeterGroup DisRes][!SetOption Info1Text X "(#PHeight#*0.4)"][!SetOption Info1Text Y "(#PHeight#*0.11)"]
IfConditionMode		=1
UpdateDivider		=10


;---- Standard Meter

[Info1IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Game#FPSViewColoredIcons#.png
	X=(#PHeight#*0.06)
	Y=(#PHeight#*0.08)
	W=(#PHeight#*0.22)
	H=(#PHeight#*0.22)
	DynamicVariables=1
[Info1IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Game#FPSViewColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.22)
	H=(#PHeight#*0.22)
	Hidden=#FPSViewColoredIcons#
	DynamicVariables=1
[Info1Text]
	Meter=String
	MeterStyle=PText | PInfo
	MeasureName=Measure_FPS
	Text=%1 FPS
	X=(#PHeight#*0.31)
	Y=(#PHeight#*0.05)
	Group=GameON

[Info2Text]
	Meter=String
	MeterStyle=PText | PSize6
	MeasureName=Measure_ScreenWidth
	MeasureName2=Measure_ScreenHeight
	Text=%1 x %2 px
	X=(#PHeight#*0.31)
	Y=(#PHeight#*0.185)
	Group=GameON | DisRes

[Info3Text]
	Meter=String
	MeterStyle=PText | PSize6
	Text=2D Mode
	X=(#PHeight#*0.4)
	Y=(#PHeight#*0.13)
	Group=GameOFF

	
;---- Skin Functions ----

[KlickFunctions]
Meter=Shape
MeterStyle=KlickFunctionsBG

[ChangePanelSize]
Meter=Shape
MeterStyle=Change-Panel-Size