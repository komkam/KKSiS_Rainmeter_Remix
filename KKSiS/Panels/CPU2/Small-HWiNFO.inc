[Variables]
;---- Style ----
@Include5=#@#Include\PanelStyleSmall.inc
;---- Sensors ----
@Include6=#@#HWiNFO-Sensors.inc


;---- Standard HWiNFO Measures ----

[Measure_CPUTemp]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#CPU2-Temp_Id#
HWiNFOSensorInstance=#CPU2-Temp_Instance#
HWiNFOEntryId		=#CPU2-Temp_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[Measure_CPUUsage]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#CPU2-Usage-Total_Id#
HWiNFOSensorInstance=#CPU2-Usage-Total_Instance#
HWiNFOEntryId		=#CPU2-Usage-Total_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[Measure_CPU0Clock]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#CPU2A-Clock_Id#
HWiNFOSensorInstance=#CPU2A-Clock_Instance#
HWiNFOEntryId		=#CPU2A-Clock_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[Measure_CPU1Clock]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#CPU2B-Clock_Id#
HWiNFOSensorInstance=#CPU2B-Clock_Instance#
HWiNFOEntryId		=#CPU2B-Clock_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[Measure_CPU2Clock]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#CPU2C-Clock_Id#
HWiNFOSensorInstance=#CPU2C-Clock_Instance#
HWiNFOEntryId		=#CPU2C-Clock_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[Measure_CPU3Clock]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#CPU2D-Clock_Id#
HWiNFOSensorInstance=#CPU2D-Clock_Instance#
HWiNFOEntryId		=#CPU2D-Clock_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[Measure_AvgCPUClock]
Measure				=Calc
Formula				=(Measure_CPU0Clock+Measure_CPU1Clock+Measure_CPU1Clock+Measure_CPU3Clock)/4
UpdateDivider		=1


;---- Standard Meter

[Info1IconA]
	Meter=Image
	ImageName=#@#Images\Icons\CPU#CPU2ColoredIcons#.png
	X=(#PHeight#*0.06)
	Y=(#PHeight#*0.08)
	W=(#PHeight#*0.22)
	H=(#PHeight#*0.22)
	DynamicVariables=1
[Info1IconB]
	Meter=Image
	ImageName=#@#Images\Icons\CPU#CPU2ColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.22)
	H=(#PHeight#*0.22)
	Hidden=#CPU2ColoredIcons#
	DynamicVariables=1
[Info1Text]
	Meter=String
	MeterStyle=PText | PInfo
	MeasureName=Measure_AvgCPUClock
	X=(#PHeight#*0.31)
	Y=(#PHeight#*0.05)
	Text=%1 MHz
	DynamicVariables=1

[Info2Text]
	Meter=String
	MeterStyle=PText | PInfo
	MeasureName=Measure_CPUTemp
	MeasureName2=Measure_CPUUsage
	Text=%1[\x00B0]#TempUnit# | %2%
	X=(#PHeight#*0.31)
	Y=(#PHeight#*0.17)
	NumOfDecimals=0
	DynamicVariables=1


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