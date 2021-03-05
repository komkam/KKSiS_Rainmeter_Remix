[Variables]
;---- Style ----
@Include5=#@#Include\PanelStyleBig.inc
;---- Sensors ----
@Include6=#@#Windows-Sensors.inc


;---- Standard MSIAB Measures ----

[Measure_CPUName]
Measure				=Registry
RegHKey				=HKEY_LOCAL_MACHINE
RegKey				=HARDWARE\DESCRIPTION\System\CentralProcessor\0
RegValue			=ProcessorNameString
RegExpSubstitute	=1
Substitute			=#CPUFilterWindows#
UpdateDivider		=-1

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

[Info1Text]
	Meter=String
	MeterStyle=PText | PSize0 | PCenterBig
	Y=(#PHeight#*0.1)
	MeasureName=Measure_CPUUsage
	Text=%1 %
	NumOfDecimals=1
	DynamicVariables=1
	
[Info2IconA]
	Meter=Image
	ImageName=#@#Images\Icons\CPU#CPUColoredIcons#.png
	X=(#PHeight#*0.65)
	Y=(#PHeight#*0.7)
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	DynamicVariables=1
[Info2IconB]
	Meter=Image
	ImageName=#@#Images\Icons\CPU#CPUColoredIcons#.png
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
	MeasureName=Measure_CPUFrequency
	Text=%1 MHz
	DynamicVariables=1

[Title]
	Meter=String
	MeasureName=Measure_CPUName
	MeterStyle=PText | PTitle2
	Text=#CPUNameWin#


;---- Graph ----

[InfoGraph]
	Meter=Line
	MeasureName=Measure_CPUUsage
	LineCount=1
	MeterStyle=GraphStyleBigPanelWindows


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