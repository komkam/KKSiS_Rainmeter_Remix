[Variables]
;---- Style ----
@Include5=#@#Include\PanelStyleMid.inc
;---- Sensors ----
@Include6=#@#Windows-Sensors.inc
@Include7=#@#MSIAB-Sensors.inc


;---- Standard MSIAB Measures ----

[Measure_CPUName]
Measure				=Registry
RegHKey				=HKEY_LOCAL_MACHINE
RegKey				=HARDWARE\DESCRIPTION\System\CentralProcessor\0
RegValue			=ProcessorNameString
RegExpSubstitute	=1
Substitute			=#CPUFilterWindows#
UpdateDivider		=-1

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

[Measure_CPUUsage2]
Measure				=Calc
Formula				=100-Measure_CPUUsage
MaxValue			=100
MinValue			=0

[Measure_CPUPower]
Measure				=Plugin
Plugin				=MSIAfterburner
DataSource			=CPU power
;SourceId			=256
UpdateDivider		=1

[Measure_CPUClock]
Measure				=Plugin
Plugin				=MSIAfterburner
DataSource			=CPU clock
;SourceId			=160
UpdateDivider		=1


;---- Standard Meter ----

[Info1IconA]
	Meter=Image
	ImageName=#@#Images\Icons\CPU#CPUColoredIcons#.png
	X=(#PHeight#*0.16+#CPUHideGraph#*#PHeight#*0.03)
	Y=(#PHeight#*0.1)
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
	MeasureName=Measure_CPUClock
	Text=%1 MHz
	DynamicVariables=1

[Info2IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Power#CPUColoredIcons#.png
	X=(-#PHeight#*0.2)r
	Y=(#PHeight#*0.20)r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	DynamicVariables=1
[Info2IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Power#CPUColoredIcons#.png
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
	MeasureName=Measure_CPUPower
	Text=%1 W
	NumOfDecimals=1
	DynamicVariables=1

[Info3IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Temp#CPUColoredIcons#.png
	X=(-#PHeight#*0.2)r
	Y=(#PHeight#*0.20)r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	DynamicVariables=1
[Info3IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Temp#CPUColoredIcons#.png
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
	MeasureName=Measure_CPUTemp
	Text=%1[\x00B0]#TempUnit#
	NumOfDecimals=1
	DynamicVariables=1

[Info4IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Usage#CPUColoredIcons#.png
	X=(-#PHeight#*0.2)r
	Y=(#PHeight#*0.20)r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	DynamicVariables=1
[Info4IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Usage#CPUColoredIcons#.png
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
	MeasureName=Measure_CPUUsage
	Text=%1%
	NumOfDecimals=1
	DynamicVariables=1

[Title]
	Meter=String
	MeasureName=Measure_CPUName
	MeterStyle=PText | PTitle
	Text=#CPUNameWin#


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
Shape=Rectangle (#PHeight#*0.05),(#PHeight#*0.8),(#PHeight#*0.9),(#PHeight#*0.006),0 | StrokeWidth 0 | Fill Color #Panel-StrokeColor#
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