[Variables]
;---- Style ----
@Include5=#@#Include\PanelStyleSmall.inc
;---- Sensors ----
@Include6=#@#HWiNFO-Sensors.inc


;---- Standard HWiNFO Measures ----

[Measure_VRAM]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#GPU-VRAM_Id#
HWiNFOSensorInstance=#GPU-VRAM_Instance#
HWiNFOEntryId		=#GPU-VRAM_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[Measure_GPUTemp]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#GPU-Temp_Id#
HWiNFOSensorInstance=#GPU-Temp_Instance#
HWiNFOEntryId		=#GPU-Temp_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[Measure_GPUUsage]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#GPU-CoreLoad_Id#
HWiNFOSensorInstance=#GPU-CoreLoad_Instance#
HWiNFOEntryId		=#GPU-CoreLoad_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1


;---- Standard Meter

[Info1IconA]
	Meter=Image
	ImageName=#@#Images\Icons\GPU#GPUColoredIcons#.png
	X=(#PHeight#*0.06)
	Y=(#PHeight#*0.08)
	W=(#PHeight#*0.22)
	H=(#PHeight#*0.22)
	DynamicVariables=1
[Info1IconB]
	Meter=Image
	ImageName=#@#Images\Icons\GPU#GPUColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.22)
	H=(#PHeight#*0.22)
	Hidden=#GPUColoredIcons#
	DynamicVariables=1
[Info1Text]
	Meter=String
	MeterStyle=PText | PInfo
	MeasureName=Measure_VRAM
	X=(#PHeight#*0.31)
	Y=(#PHeight#*0.05)
	Text=%1 MB
	DynamicVariables=1

[Info2Text]
	Meter=String
	MeterStyle=PText | PInfo
	MeasureName=Measure_GPUTemp
	MeasureName2=Measure_GPUUsage
	Text=%1[\x00B0]#TempUnit# | %2%
	X=(#PHeight#*0.31)
	Y=(#PHeight#*0.17)
	NumOfDecimals=0
	DynamicVariables=1


;---- Skin Functions ----

[KlickFunctions]
Meter=Shape
MeterStyle=KlickFunctionsBG

[ChangePanelSize]
Meter=Shape
MeterStyle=Change-Panel-Size