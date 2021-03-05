[Variables]
;---- Style ----
@Include5=#@#Include\PanelStyleBig.inc
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
IfAboveAction		=[!HideMeterGroup GameOFF][!ShowMeterGroup GameON][!HideMeter Info5IconB]
IfCondition			=(#FPSViewHideAVGFPS# = 1)
IfTrueAction		=[!HideMeterGroup AVGFPS]
IfCondition2		=(#FPSViewHideDisplayRes# = 1)
IfTrueAction2		=[!HideMeterGroup DisRes]
IfCondition3		=(Measure_FPS = 0) && (#FPSViewColoredIcons# = 0)
IfTrueAction3		=[!ShowMeter Info7IconB]
IfConditionMode		=1
UpdateDivider		=10

[Measure_MinFPS]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#GPU-FPS_Id#
HWiNFOSensorInstance=#GPU-FPS_Instance#
HWiNFOEntryId		=#GPU-FPS_EntryId#
HWiNFOType			=MinimumValue
UpdateDivider		=10

[Measure_MaxFPS]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#GPU-FPS_Id#
HWiNFOSensorInstance=#GPU-FPS_Instance#
HWiNFOEntryId		=#GPU-FPS_EntryId#
HWiNFOType			=MaximumValue
UpdateDivider		=10

[Measure_AvgFPS]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#GPU-FPS_Id#
HWiNFOSensorInstance=#GPU-FPS_Instance#
HWiNFOEntryId		=#GPU-FPS_EntryId#
HWiNFOType			=AverageValue
UpdateDivider		=10


;---- Standard Meter ----

[Info1Text]
	Meter=String
	MeterStyle=PText | PSize8
	StringAlign=left
	X=(#PHeight#*0.07)
	Y=(#PHeight#*0.05)
	MeasureName=Measure_MinFPS
	Text=Min: %1
	Group=GameON | AVGFPS

[Info2Text]
	Meter=String
	MeterStyle=PText | PSize8
	StringAlign=left
	X=(#PHeight#*0.07)
	Y=(#PHeight#*0.15)
	MeasureName=Measure_AvgFPS
	Text=Avg: %1
	Group=GameON | AVGFPS

[Info3Text]
	Meter=String
	MeterStyle=PText | PSize8
	StringAlign=left
	X=(#PHeight#*0.07)
	Y=(#PHeight#*0.25)
	MeasureName=Measure_MaxFPS
	Text=Max: %1
	Group=GameON | AVGFPS
	
[Info4Text]
	Meter=String
	MeterStyle=PText | PCenterBig | PSize0
	Y=(#PHeight#*0.06)
	MeasureName=Measure_FPS
	Text=%1
	Group=GameON
	
[Info5IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Game#FPSViewColoredIcons#.png
	X=(#PHeight#*0.78)
	Y=(#PHeight#*0.27)
	W=(#PHeight#*0.5)
	H=(#PHeight#*0.5)
	DynamicVariables=1
	Group=GameOFF
[Info5IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Game#FPSViewColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.5)
	H=(#PHeight#*0.5)
	Hidden=#FPSViewColoredIcons#
	DynamicVariables=1

[Info5Text]
	Meter=String
	MeterStyle=PText | PCenterBig | PSize8
	Y=(#PHeight#*0.2)
	Text=2D Mode
	Group=GameOFF

[Title]
	Meter=String
	MeterStyle=PText | PTitle2
	Text=#FPSViewName#

;---- Graph ----

[GraphLabel1]
	Meter=String
	MeterStyle=PText | PSize10
	StringAlign=Left
	FontColor=#Panel-BarFillColor1#
	X=(#PHeight#*0.07)
	Y=(#PHeight#*0.34)
	Text=Framerate (FPS)
	Group=GameON

[MeterFPSViewGraph]
	Meter=Line
	MeasureName=Measure_FPS
	LineCount=1
	MeterStyle=GraphStyleLeft
	W=(#PHeight#*1.985)
	Group=GameON
	UpdateDivider=5


;---- Skin Functions ----

[KlickFunctions]
Meter=Shape
MeterStyle=KlickFunctionsBG

[ChangePanelSize]
Meter=Shape
MeterStyle=Change-Panel-Size