[Variables]
;---- Style ----
@Include5=#@#Include\PanelStyleSmall.inc
;---- Sensors ----
@Include6=#@#Windows-Sensors.inc


;---- Standard MSIAB Measures ----

[Measure_CPUFrequency]
Measure				=Registry
RegHKey				=HKEY_LOCAL_MACHINE
RegKey				=HARDWARE\DESCRIPTION\System\CentralProcessor\0
RegValue			=~MHz
UpdateDivider		=-1

[Measure_CPUUsage]
Measure				=CPU
Processor			=0
UpdateDivider		=1


;---- Standard Meter ----

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
	MeasureName=Measure_CPUFrequency
	X=(#PHeight#*0.31)
	Y=(#PHeight#*0.05)
	Text=%1 MHz
	DynamicVariables=1

[Info2Text]
	Meter=String
	MeterStyle=PText | PInfo
	MeasureName=Measure_CPUUsage
	Text=%1%
	X=(#PHeight#*0.31)
	Y=(#PHeight#*0.17)
	NumOfDecimals=1
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