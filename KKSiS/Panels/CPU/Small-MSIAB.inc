[Variables]
;---- Style ----
@Include5=#@#Include\PanelStyleSmall.inc
;---- Sensors ----
@Include6=#@#MSIAB-Sensors.inc


;---- Standard MSIAB Measures ----

[Measure_CPUTemp]
Measure				=Plugin
Plugin				=MSIAfterburner
DataSource			=CPU temperature
;SourceId			=128
UpdateDivider		=1

[Measure_CPUUsage]
Measure				=Plugin
Plugin				=MSIAfterburner
DataSource			=CPU usage
;SourceId			=144
UpdateDivider		=1

[Measure_CPUClock]
Measure				=Plugin
Plugin				=MSIAfterburner
DataSource			=CPU clock
;SourceId			=160
UpdateDivider		=1

;---- Standard Meter

[Info1IconA]
	Meter=Image
	ImageName=#@#Images\Icons\CPU#CPUColoredIcons#.png
	X=(#PHeight#*0.06)
	Y=(#PHeight#*0.08)
	W=(#PHeight#*0.22)
	H=(#PHeight#*0.22)
	DynamicVariables=1
[Info1IconB]
	Meter=Image
	ImageName=#@#Images\Icons\CPU#CPUColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.22)
	H=(#PHeight#*0.22)
	Hidden=#CPUColoredIcons#
	DynamicVariables=1
[Info1Text]
	Meter=String
	MeterStyle=PText | PInfo
	MeasureName=Measure_CPUClock
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