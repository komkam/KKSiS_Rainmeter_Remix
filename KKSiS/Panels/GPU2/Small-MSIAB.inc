[Variables]
;---- Style ----
@Include5=#@#Include\PanelStyleSmall.inc
;---- Sensors ----
@Include6=#@#MSIAB-Sensors.inc


;---- Standard MSIAB Measures ----

[Measure_GPUTemp]
Measure				=Plugin
Plugin				=MSIAfterburner
GPU					=1
SourceId			=0
UpdateDivider		=1

[Measure_GPUUsage]
Measure				=Plugin
Plugin				=MSIAfterburner
GPU					=1
SourceId			=48
UpdateDivider		=1

[Measure_VRAM]
Measure				=Plugin
Plugin				=MSIAfterburner
GPU					=1
SourceId			=49
UpdateDivider		=1


;---- Standard Meter

[Info1IconA]
	Meter=Image
	ImageName=#@#Images\Icons\GPU#GPU2ColoredIcons#.png
	X=(#PHeight#*0.06)
	Y=(#PHeight#*0.08)
	W=(#PHeight#*0.22)
	H=(#PHeight#*0.22)
	DynamicVariables=1
[Info2IconB]
	Meter=Image
	ImageName=#@#Images\Icons\GPU#GPU2ColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.22)
	H=(#PHeight#*0.22)
	Hidden=#GPU2ColoredIcons#
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

[GPU2Title]
	Meter=String
	MeterStyle=PText | PSize8
	X=(#PHeight#*0.07)
	Y=(#PHeight#*0.05)
	Text=GPU#2
	Hidden=0

;---- Skin Functions ----

[KlickFunctions]
Meter=Shape
MeterStyle=KlickFunctionsBG

[ChangePanelSize]
Meter=Shape
MeterStyle=Change-Panel-Size