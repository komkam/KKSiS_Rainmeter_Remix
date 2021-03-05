[Variables]
;---- Style ----
@Include5=#@#Include\PanelStyleMid.inc
;---- Sensors ----
@Include6=#@#HWiNFO-Sensors.inc


;---- Standard HWiNFO Measures ----

[Measure_CPUName]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#CPU-Temp_Id#
HWiNFOSensorInstance=#CPU-Temp_Instance#
HWiNFOEntryId		=#CPU-Temp_EntryId#
HWiNFOType			=SensorName
RegExpSubstitute	=1
Substitute			=#CPUFilterHWiNFO#
UpdateDivider		=-1

[Measure_CPUTemp]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#CPU-Temp_Id#
HWiNFOSensorInstance=#CPU-Temp_Instance#
HWiNFOEntryId		=#CPU-Temp_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[Measure_CPUUsage]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#CPU-Usage-Total_Id#
HWiNFOSensorInstance=#CPU-Usage-Total_Instance#
HWiNFOEntryId		=#CPU-Usage-Total_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[Measure_CPUUsage2]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#CPU-Usage-Total_Id#
HWiNFOSensorInstance=#CPU-Usage-Total_Instance#
HWiNFOEntryId		=#CPU-Usage-Total_EntryId#
HWiNFOType			=CurrentValue
InvertMeasure		=1
MaxValue			=100
MinValue			=0
UpdateDivider		=1

[Measure_CPUVCore]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#CPU-VCore_Id#
HWiNFOSensorInstance=#CPU-VCore_Instance#
HWiNFOEntryId		=#CPU-VCore_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[Measure_CPUPower]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#CPU-PackagePwr_Id#
HWiNFOSensorInstance=#CPU-PackagePwr_Instance#
HWiNFOEntryId		=#CPU-PackagePwr_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[Measure_CPU0Clock]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#CPUA-Clock_Id#
HWiNFOSensorInstance=#CPUA-Clock_Instance#
HWiNFOEntryId		=#CPUA-Clock_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[Measure_CPU1Clock]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#CPUB-Clock_Id#
HWiNFOSensorInstance=#CPUB-Clock_Instance#
HWiNFOEntryId		=#CPUB-Clock_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[Measure_CPU2Clock]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#CPUC-Clock_Id#
HWiNFOSensorInstance=#CPUC-Clock_Instance#
HWiNFOEntryId		=#CPUC-Clock_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[Measure_CPU3Clock]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#CPUD-Clock_Id#
HWiNFOSensorInstance=#CPUD-Clock_Instance#
HWiNFOEntryId		=#CPUD-Clock_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[Measure_CPUFAN1]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#CPU-FAN1_Id#
HWiNFOSensorInstance=#CPU-FAN1_Instance#
HWiNFOEntryId		=#CPU-FAN1_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[Measure_CPUFAN2_Pump]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#CPU-FAN2_Id#
HWiNFOSensorInstance=#CPU-FAN2_Instance#
HWiNFOEntryId		=#CPU-FAN2_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1
IfCondition=(Measure_CPUFAN2_Pump > 0)
IfTrueAction=[!SetOption Info4Text Text "%1 | %2"]
IfFalseAction=[!SetOption Info4Text Text "%1 rpm"]

[Measure_AvgCPUClock]
Measure				=Calc
Formula				=(Measure_CPU0Clock+Measure_CPU1Clock+Measure_CPU1Clock+Measure_CPU3Clock)/4
UpdateDivider		=1


;---- Standard Meter ----

[Info1IconA]
	Meter=Image
	ImageName=#@#Images\Icons\CPU#CPUColoredIcons#.png
	X=(#PHeight#*0.13+#CPUHideGraph#*#PHeight#*0.03)
	Y=(#PHeight#*0.06)
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	DynamicVariables=1
[Info1IconB]
	Meter=Image
	ImageName=#@#Images\Icons\CPU#CPUColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	Hidden=#CPUColoredIcons#
	DynamicVariables=1
[Info1Text]
	Meter=String
	MeterStyle=PText | PInfo
	MeasureName=Measure_AvgCPUClock
	Text=%1 MHz
	DynamicVariables=1

[Info2IconA]
	Meter=Image
	ImageName=#@#Images\Icons\VCC#CPUColoredIcons#.png
	X=(-#PHeight#*0.2)r
	Y=(#PHeight#*0.16)r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	DynamicVariables=1
[Info2IconB]
	Meter=Image
	ImageName=#@#Images\Icons\VCC#CPUColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	Hidden=#CPUColoredIcons#
	DynamicVariables=1
[Info2Text]
	Meter=String
	MeterStyle=PText | PInfo
	MeasureName=Measure_CPUVcore
	Text=%1 V
	NumOfDecimals=3
	DynamicVariables=1

[Info3IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Power#CPUColoredIcons#.png
	X=(-#PHeight#*0.2)r
	Y=(#PHeight#*0.16)r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	DynamicVariables=1
[Info3IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Power#CPUColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	Hidden=#CPUColoredIcons#
	DynamicVariables=1
[Info3Text]
	Meter=String
	MeterStyle=PText | PInfo
	MeasureName=Measure_CPUPower
	Text=%1 W
	NumOfDecimals=1
	DynamicVariables=1

[Info4IconA]
	Meter=Image
	ImageName=#@#Images\Icons\CPUCooler#CPUColoredIcons#.png
	X=(-#PHeight#*0.2)r
	Y=(#PHeight#*0.16)r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	DynamicVariables=1
[Info4IconB]
	Meter=Image
	ImageName=#@#Images\Icons\CPUCooler#CPUColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	Hidden=#CPUColoredIcons#
	DynamicVariables=1
[Info4Text]
	Meter=String
	MeterStyle=PText | PInfo
	MeasureName=Measure_CPUFAN1
	MeasureName2=Measure_CPUFAN2_Pump
	Text=%1 rpm
	NumOfDecimals=0
	DynamicVariables=1

[Info5IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Temp#CPUColoredIcons#.png
	X=(-#PHeight#*0.2)r
	Y=(#PHeight#*0.16)r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	DynamicVariables=1
[Info5IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Temp#CPUColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	Hidden=#CPUColoredIcons#
	DynamicVariables=1
[Info5Text]
	Meter=String
	MeterStyle=PText | PInfo
	MeasureName=Measure_CPUTemp
	Text=%1[\x00B0]#TempUnit#
	NumOfDecimals=1
	DynamicVariables=1

[Info6IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Usage#CPUColoredIcons#.png
	X=(-#PHeight#*0.2)r
	Y=(#PHeight#*0.16)r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	DynamicVariables=1
[Info6IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Usage#CPUColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	Hidden=#CPUColoredIcons#
	DynamicVariables=1
[Info6Text]
	Meter=String
	MeterStyle=PText | PInfo
	MeasureName=Measure_CPUUsage
	Text=%1%
	NumOfDecimals=1
	DynamicVariables=1

[Title]
	Meter=String
	MeasureName=Measure_CPUName
	MeterStyle=PText | PTitle
	Text=#CPUName#


;---- Bar ----

[Bar1]
Meter=Shape
MeterStyle=BarStyle-VRx1
UpdateDivider=1
Hidden=#CPUHideGraph#

[Bar1Measure]
Meter=Bar
MeterStyle=BarStyle-VRx1Measure
MeasureName=Measure_CPUUsage2
UpdateDivider=1
Hidden=#CPUHideGraph#

[Bar1Stroke]
Meter=Shape
MeterStyle=BarStyle-VRx1Stroke
UpdateDivider=1
Hidden=#CPUHideGraph#

[Bar1Marker]
Meter=Shape
Shape=Rectangle (#PHeight#*0.05),(#PHeight#*0.92),(#PHeight#*0.9),(#PHeight#*0.006),0 | StrokeWidth 0 | Fill Color #Panel-StrokeColor#
UpdateDivider=1
DynamicVariables=1
Hidden=#CPUHideGraph#


;---- Skin Functions ----

[KlickFunctions]
Meter=Shape
MeterStyle=KlickFunctionsBG
LeftMouseUpAction=[!CommandMeasure SpecialFunction Run]

[SpecialFunction]
Measure=Plugin
Plugin=RunCommand
Parameter=taskmgr

[ChangePanelSize]
Meter=Shape
MeterStyle=Change-Panel-Size