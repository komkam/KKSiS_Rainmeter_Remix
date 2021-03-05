[Variables]
;---- Style ----
@Include5=#@#Include\PanelStyleMid.inc
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
IfAboveAction		=[!HideMeterGroup GameOFF][!ShowMeterGroup GameON][!HideMeter Info6IconB]
IfCondition			=(#FPSViewHideAVGFPS# = 1)
IfTrueAction		=[!HideMeterGroup AVGFPS][!SetOption Info1Text Y "(#PHeight#*0.06)"]
IfCondition2		=(#FPSViewHideDisplayRes# = 1)
IfTrueAction2		=[!HideMeterGroup DisRes][!SetOption MeterFPSViewGraph H "(#PHeight#*0.6)"]
IfCondition3		=(Measure_FPS = 0) && (#FPSViewColoredIcons# = 0)
IfTrueAction3		=[!ShowMeter Info6IconB]
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
	MeterStyle=PText | PCenterMid | PSize0
	Y=(#PHeight#*0.04)
	MeasureName=Measure_FPS
	Text=%1
	Group=GameON
	
[Info2Text]
	Meter=String
	MeterStyle=PText | PSize8
	StringAlign=left
	X=(#PHeight#*0.07)
	Y=(#PHeight#*0.25)
	MeasureName=Measure_MinFPS
	Text=Min: %1
	Group=GameON | AVGFPS

[Info3Text]
	Meter=String
	MeterStyle=PText | PCenterMid | PSize8
	StringAlign=center
	Y=(#PHeight#*0.25)
	MeasureName=Measure_AvgFPS
	Text=Avg: %1
	Group=GameON | AVGFPS

[Info4Text]
	Meter=String
	MeterStyle=PText | PSize8
	StringAlign=right
	X=(#PHeight#*1.02)
	Y=(#PHeight#*0.25)
	MeasureName=Measure_MaxFPS
	Text=Max: %1
	Group=GameON | AVGFPS
	
[Info5IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Monitor#FPSViewColoredIcons#.png
	X=(#PHeight#*0.17)
	Y=(#PHeight#*0.80)
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	DynamicVariables=1
	Group=GameON | DisRes
[Info5IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Monitor#FPSViewColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	Hidden=#FPSViewColoredIcons#
	DynamicVariables=1
	Group=GameON | DisRes
[Info5TextA]
	Meter=String
	MeterStyle=PText | PInfo
	MeasureName=Measure_ScreenWidth
	MeasureName2=Measure_ScreenHeight
	Text=%1 x %2
	Group=GameON | DisRes
[Info5TextB]
	Meter=String
	MeterStyle=PText | PSize8
	X=(#PHeight#*0.212)
	Y=(#PHeight#*0.808)
	Text=#FPSViewDisplayID#
	DynamicVariables=1
	Group=GameON | DisRes

[Info6IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Game#FPSViewColoredIcons#.png
	X=(#PHeight#*0.28)
	Y=(#PHeight#*0.27)
	W=(#PHeight#*0.5)
	H=(#PHeight#*0.5)
	DynamicVariables=1
	Group=GameOFF
[Info6IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Game#FPSViewColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.5)
	H=(#PHeight#*0.5)
	Hidden=#FPSViewColoredIcons#
	DynamicVariables=1
[Info6Text]
	Meter=String
	MeterStyle=PText | PCenterMid | PSize8
	Y=(#PHeight#*0.2)
	Text=2D Mode
	Group=GameOFF

[Title]
	Meter=String
	MeterStyle=PText | PTitle
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
	MeterStyle=GraphStyle
	H=(#PHeight#*0.45)
	Group=GameON
	UpdateDivider=5


;---- Skin Functions ----

[KlickFunctions]
Meter=Shape
MeterStyle=KlickFunctionsBG

[ChangePanelSize]
Meter=Shape
MeterStyle=Change-Panel-Size